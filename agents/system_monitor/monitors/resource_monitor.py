"""
Periodic host thresholds (RAM/disk/CPU), battery, and top-app memory/CPU sampling.

Per-app battery use is not exposed by the OS; high CPU on battery is used as a practical proxy
in :meth:`ResourceMonitor._emit_top_app_consumers`.
"""
import time
import subprocess

import psutil


def get_windows_battery_percent() -> float | None:
    """
    Get battery percentage from Windows WMI (matches Windows taskbar display).
    Falls back to psutil if WMI fails.
    """
    try:
        # Hide console window on Windows
        startupinfo = None
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            ['powershell', '-Command', '(Get-WmiObject Win32_Battery).EstimatedChargeRemaining'],
            capture_output=True, text=True, timeout=5,
            startupinfo=startupinfo
        )
        if result.returncode == 0 and result.stdout.strip():
            return float(result.stdout.strip())
    except:
        pass
    # Fallback to psutil
    try:
        bat = psutil.sensors_battery()
        if bat:
            return float(bat.percent)
    except:
        pass
    return None
from config import (
    RAM_HIGH_PERCENT,
    BATTERY_CRITICAL_PERCENT,
    BATTERY_DRAIN_THRESHOLD_PERCENT,
    DISK_HIGH_PERCENT,
    CPU_HIGH_PERCENT,
    POLL_INTERVAL_RESOURCE,
    TOP_APPS_REPORT_INTERVAL_SEC,
    TOP_APPS_REPORT_RANK,
    TOP_APPS_CPU_SAMPLE_SLEEP_SEC,
    BATTERY_HISTORY_SAMPLE_INTERVAL_SEC,
    BATTERY_FAST_DRAIN_RATE_PCT_PER_H,
    BATTERY_RISK_MEDIUM_DRAIN_PCT_PER_H,
    BATTERY_RISK_HIGH_DRAIN_PCT_PER_H,
    BATTERY_FAST_DRAIN_SHORT_WINDOW_MIN,
    BATTERY_FAST_DRAIN_SHORT_DROP_PCT,
    APP_HIGH_MEMORY_MB,
    APP_HIGH_BATTERY_CPU_PERCENT,
)
from monitors.app_tracker import normalize_process_name
from utils.battery_history import BatteryHourlyTracker, drain_risk_level_from_rate
from utils.db_queue import log_event
from utils.agent_logger import logger

_SKIP_CPU_NAMES = frozenset(
    s.lower() for s in ("System Idle Process", "Idle", "Registry", "Memory Compression")
)


class ResourceMonitor:
    """
    Polls ``psutil`` for resource usage, battery state, and top processes.

    Emits ``SystemPerformance`` and ``DeviceControl`` events suitable for the SIEM backend.
    Battery drain alerts include Goal 3 ``riskLevel`` derived from estimated %/h drain.
    """

    def __init__(self) -> None:
        """Initialize trackers, hysteresis flags, and the rolling battery history buffer."""
        self.last_battery = None
        self._logged_initial_charger_state = False
        self.last_cpu_alerted = False
        self.last_mem_alerted = False
        self.last_disk_alerted = False
        self._last_top_apps_report_at = 0.0
        self._battery_hourly = BatteryHourlyTracker(
            sample_interval_sec=BATTERY_HISTORY_SAMPLE_INTERVAL_SEC,
            fast_drain_rate_pct_per_h=BATTERY_FAST_DRAIN_RATE_PCT_PER_H,
            risk_medium_rate=BATTERY_RISK_MEDIUM_DRAIN_PCT_PER_H,
            risk_high_rate=BATTERY_RISK_HIGH_DRAIN_PCT_PER_H,
            fast_drain_short_window_min=BATTERY_FAST_DRAIN_SHORT_WINDOW_MIN,
            fast_drain_short_drop_pct=BATTERY_FAST_DRAIN_SHORT_DROP_PCT,
        )
        # Track when apps were first seen to avoid false positives on startup
        self._app_first_seen = {}
        self._app_high_battery_alerted = set()

        psutil.cpu_percent()

    def poll(self) -> None:
        """Run one full resource cycle: optional top-app report, then threshold checks."""
        now = time.time()
        if now - self._last_top_apps_report_at >= TOP_APPS_REPORT_INTERVAL_SEC:
            self._last_top_apps_report_at = now
            self._emit_top_app_consumers()
        self._check_memory()
        self._check_battery()
        self._check_cpu()
        self._check_disk()

    def _emit_top_app_consumers(self) -> None:
        """
        Emit ``APP_TOP_CONSUMERS_REPORT`` with top processes by RSS and short CPU sample.

        On battery, high CPU rank is a common proxy for power-heavy workloads.
        """
        try:
            bat = psutil.sensors_battery()
            on_battery = bool(bat and not bat.power_plugged)

            for p in psutil.process_iter():
                try:
                    p.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            time.sleep(TOP_APPS_CPU_SAMPLE_SLEEP_SEC)

            rows = []
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    raw_name = p.info.get("name") or ""
                    if not raw_name:
                        continue
                    if raw_name.strip().lower() in _SKIP_CPU_NAMES:
                        continue
                    rss = p.memory_info().rss
                    if rss <= 0:
                        continue
                    cpu = p.cpu_percent(interval=None)
                    exe = normalize_process_name(raw_name)
                    rows.append(
                        {
                            "exe": exe,
                            "mb": round(rss / (1024 * 1024), 1),
                            "cpu": round(cpu, 1),
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            n = max(3, min(TOP_APPS_REPORT_RANK, 12))
            by_mem = sorted(rows, key=lambda x: -x["mb"])[:n]
            by_cpu = sorted(rows, key=lambda x: -x["cpu"])[:n]

            meta = {
                "topMemory": [{"exe": x["exe"], "mb": x["mb"]} for x in by_mem],
                "topCpu": [{"exe": x["exe"], "cpu": x["cpu"]} for x in by_cpu],
                "onBattery": on_battery,
            }
            if bat:
                # Use Windows WMI for accurate battery percentage (matches taskbar)
                percent_raw = get_windows_battery_percent()
                if percent_raw is None:
                    percent_raw = bat.percent
                meta["batteryPercent"] = round(percent_raw, 1)
                meta["powerPlugged"] = bool(bat.power_plugged)

            # --- Proactive App Alerts (Battery/Memory) ---
            now = time.time()
            # Track app start times to avoid false positives on startup
            for app in rows:
                app_key = app["exe"]
                if app_key not in self._app_first_seen:
                    self._app_first_seen[app_key] = now
            
            # Clean up old entries (apps that are no longer running)
            current_apps = {app["exe"] for app in rows}
            for app_key in list(self._app_first_seen.keys()):
                if app_key not in current_apps:
                    del self._app_first_seen[app_key]
                    self._app_high_battery_alerted.discard(app_key)

            for app in by_mem:
                if app["mb"] > APP_HIGH_MEMORY_MB:
                    log_event(
                        event_type="AppBehaviour",
                        user_action="APP_HIGH_MEMORY",
                        app_name=app["exe"],
                        metadata={"memory_mb": app["mb"], "severity": "MEDIUM"}
                    )

            if on_battery:
                for app in by_cpu:
                    app_key = app["exe"]
                    # Only alert if app has been running for >30 seconds (avoid startup spikes)
                    app_runtime = now - self._app_first_seen.get(app_key, now)
                    if app["cpu"] > APP_HIGH_BATTERY_CPU_PERCENT and app_runtime > 30:
                        # Only alert once per app session
                        if app_key not in self._app_high_battery_alerted:
                            self._app_high_battery_alerted.add(app_key)
                            # Log high CPU on battery (battery drain indicator)
                            log_event(
                                event_type="AppBehaviour",
                                user_action="APP_HIGH_BATTERY",
                                app_name=app["exe"],
                                metadata={
                                    "cpu_percent": app["cpu"], 
                                    "severity": "MEDIUM", 
                                    "runtime_sec": round(app_runtime),
                                    "on_battery": True,
                                    "message": f"{app['exe']} is using high CPU ({app['cpu']}%) on battery, causing battery drain"
                                }
                            )
                            # Also log as battery drain event
                            log_event(
                                event_type="SystemPerformance",
                                user_action="APP_BATTERY_DRAIN",
                                app_name=app["exe"],
                                metadata={
                                    "app_name": app["exe"],
                                    "cpu_percent": app["cpu"],
                                    "battery_percent": meta.get("batteryPercent"),
                                    "severity": "HIGH",
                                    "message": f"{app['exe']} is draining battery with {app['cpu']}% CPU usage"
                                }
                            )

            log_event(
                event_type="SystemPerformance",
                user_action="APP_TOP_CONSUMERS_REPORT",
                metadata=meta,
            )
        except Exception as e:
            logger.error(f"Top app consumers error: {e}")

    def _check_memory(self) -> None:
        """Emit ``HIGH_MEMORY_USAGE`` when system RAM crosses the configured threshold (with hysteresis)."""
        try:
            mem = psutil.virtual_memory()
            if mem.percent >= RAM_HIGH_PERCENT:
                if not self.last_mem_alerted:
                    log_event(
                        event_type="SystemPerformance",
                        user_action="HIGH_MEMORY_USAGE",
                        metadata={"memoryUsage": round(mem.percent, 1), "available_mb": round(mem.available / (1024*1024), 2)}
                    )
                    self.last_mem_alerted = True
            elif mem.percent < (RAM_HIGH_PERCENT - 5.0):
                self.last_mem_alerted = False
        except Exception as e:
            logger.error(f"Memory check error: {e}")

    def _check_battery(self) -> None:
        """
        Update hourly battery samples, emit charger plug/unplug, drain alerts, and critical low.

        ``BATTERY_DRAIN_ALERT`` metadata merges rolling-window metrics (consumption, rate,
        ``riskLevel``) and tick-local ``drainPercent``. ``riskLevel`` follows Goal 3 bands.
        """
        try:
            bat = psutil.sensors_battery()
            if not bat:
                return

            # Use Windows WMI for accurate battery percentage (matches taskbar)
            percent_raw = get_windows_battery_percent()
            if percent_raw is None:
                percent_raw = bat.percent
            percent = round(percent_raw, 1)
            charging = bat.power_plugged
            time_left = getattr(bat, "secsleft", psutil.POWER_TIME_UNKNOWN)

            self._battery_hourly.add_sample(time.time(), percent, charging)

            meta = {"batteryPercent": percent, "powerPlugged": charging}
            if time_left != psutil.POWER_TIME_UNKNOWN and time_left > 0:
                meta["timeRemainingMins"] = round(time_left / 60, 1)

            if not self._logged_initial_charger_state:
                self._logged_initial_charger_state = True
                act0 = "CHARGER_PLUGGED_IN" if charging else "CHARGER_UNPLUGGED"
                meta0 = {**meta, "initialReading": True}
                log_event("SystemPerformance", act0, metadata=meta0)
                log_event("DeviceControl", act0, metadata=meta0)

            if self.last_battery is not None:
                old_percent = self.last_battery["percent"]
                old_charging = self.last_battery["charging"]

                if charging != old_charging:
                    act = "CHARGER_PLUGGED_IN" if charging else "CHARGER_UNPLUGGED"
                    log_event("SystemPerformance", act, metadata=meta)
                    log_event("DeviceControl", act, metadata=meta)

                if not charging and not old_charging:
                    drop = old_percent - percent
                    if drop >= BATTERY_DRAIN_THRESHOLD_PERCENT:
                        hourly = self._battery_hourly.build_metrics()
                        alert_meta = {k: v for k, v in hourly.items() if v is not None}
                        alert_meta.update(meta)
                        alert_meta["drainPercent"] = round(drop, 1)
                        alert_meta["eventType"] = "BATTERY_DRAIN_ALERT"

                        hr = hourly.get("batteryDrainRatePerHour")
                        if hr is None:
                            interval_h = max(POLL_INTERVAL_RESOURCE / 3600.0, 1e-9)
                            instant_rate = drop / interval_h
                            alert_meta["batteryDrainRatePerHour"] = round(instant_rate, 2)
                            alert_meta["riskLevel"] = drain_risk_level_from_rate(instant_rate)
                            if hourly.get("batteryConsumedLastHour") is None:
                                alert_meta["batteryConsumedLastHour"] = round(min(100.0, drop), 2)
                        else:
                            alert_meta["riskLevel"] = drain_risk_level_from_rate(float(hr))

                        if drop >= (BATTERY_DRAIN_THRESHOLD_PERCENT * 2):
                            alert_meta["suddenDrop"] = True

                        log_event("SystemPerformance", "BATTERY_DRAIN_ALERT", metadata=alert_meta)

                if not charging and percent <= BATTERY_CRITICAL_PERCENT and old_percent > BATTERY_CRITICAL_PERCENT:
                    log_event("SystemPerformance", "BATTERY_CRITICAL", metadata=meta)

            self.last_battery = {"percent": percent, "charging": charging}
        except Exception as e:
            logger.error(f"Battery check error: {e}")

    def _check_cpu(self) -> None:
        """Emit ``HIGH_CPU_USAGE`` when aggregate CPU exceeds the threshold (with hysteresis)."""
        try:
            cpu = psutil.cpu_percent(interval=None)
            if cpu >= CPU_HIGH_PERCENT:
                if not self.last_cpu_alerted:
                    log_event(
                        event_type="SystemPerformance",
                        user_action="HIGH_CPU_USAGE",
                        metadata={"cpuUsage": round(cpu, 1)}
                    )
                    self.last_cpu_alerted = True
            elif cpu < 70.0:
                self.last_cpu_alerted = False
        except Exception as e:
            logger.error(f"CPU check error: {e}")

    def _check_disk(self) -> None:
        """Emit ``HIGH_DISK_USAGE`` when ``C:\\`` usage exceeds the threshold (with hysteresis)."""
        try:
            disk = psutil.disk_usage("C:\\")
            if disk.percent >= DISK_HIGH_PERCENT:
                if not self.last_disk_alerted:
                    log_event(
                        event_type="SystemPerformance",
                        user_action="HIGH_DISK_USAGE",
                        metadata={"diskUsagePercent": round(disk.percent, 1)}
                    )
                    self.last_disk_alerted = True
            elif disk.percent < (DISK_HIGH_PERCENT - 5.0):
                self.last_disk_alerted = False
        except Exception as e:
            logger.error(f"Disk check error: {e}")
