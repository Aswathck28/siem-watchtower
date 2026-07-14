"""
Per-process application open/close tracking for whitelisted desktop apps.
Uses case-insensitive matching; on Windows, process names from psutil are often
None until Process.name() is called — we always resolve the executable basename.
"""
from __future__ import annotations

import os
import platform
import sys
import time
import traceback
from typing import Iterator, Optional, Tuple

import psutil

from config import (
    APP_HIGH_MEMORY_MB,
    APP_HIGH_BATTERY_CPU_PERCENT,
    APP_TRACKING_DEBUG_VERBOSE,
    APP_TRACKING_LOG_ALL_PROCESSES,
)
from utils.db_queue import log_event
from utils.agent_logger import logger


def normalize_process_name(name: str) -> str:
    """
    Return the bare executable filename. psutil sometimes returns a full path on Windows;
    matching must use the basename only.
    """
    if not name:
        return ""
    n = name.strip()
    if "\\" in n or "/" in n:
        n = os.path.basename(n)
    return n


def resolve_tracked_app(process_name: str) -> Optional[str]:
    """
    Map a Windows process executable basename to a canonical display name.
    All comparisons use lowercase; order matters (Notepad++ before Notepad).
    """
    if not process_name:
        return None
    base = normalize_process_name(process_name)
    nl = base.lower().strip()
    if not nl:
        return None
    # Notepad++ (notepad++.exe, notepad++.64.exe, etc.)
    if "notepad++" in nl:
        return "Notepad++"
    # Plain Notepad — exclude any name that still looks like Notepad++
    if "notepad" in nl and "++" not in nl:
        return "Notepad"
    if "winword" in nl:
        return "Microsoft Word"
    if "excel" in nl:
        return "Microsoft Excel"
    if "powerpnt" in nl:
        return "Microsoft PowerPoint"
    if "codeblocks" in nl:
        return "CodeBlocks"
    if "chrome" in nl and (".exe" in nl or nl == "chrome"):
        return "Google Chrome"
    if "msedge" in nl and (".exe" in nl or nl == "msedge"):
        return "Microsoft Edge"
    if "firefox.exe" == nl:
        return "Mozilla Firefox"
    # VS Code (Code.exe) / Insiders — avoid matching CodeBlocks (no "insider" in that name)
    if nl == "code.exe" or (nl.startswith("code") and "insider" in nl):
        return "Visual Studio Code"
    return None


def _best_exe_basename(proc: psutil.Process, name_hint: Optional[str]) -> str:
    """
    Prefer the filesystem basename from exe() (accurate for notepad++.64.exe, etc.);
    fall back to name() / hint when access fails.
    """
    for candidate in (
        lambda: proc.exe(),
        lambda: proc.name(),
    ):
        try:
            raw = candidate()
            if raw:
                base = normalize_process_name(str(raw))
                if base:
                    return base
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue
    if name_hint:
        return normalize_process_name(name_hint)
    return ""


def iter_pid_exe_name_process() -> Iterator[Tuple[int, str, psutil.Process]]:
    """
    Yield (pid, executable_filename, Process) for each running process.
    Uses exe() basename when available so alternate bitness / renamed binaries match.
    """
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid = p.info.get("pid")
            if pid is None:
                continue
            hint = p.info.get("name") or p.info.get("exe")
            name = _best_exe_basename(p, hint)
            if not name:
                continue
            yield pid, name, p
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


class AppTracker:
    """Tracks OPEN/CLOSE and peak CPU/RAM for resolved tracked applications by PID."""

    def __init__(self):
        self.active_processes = {}
        self.alert_cache = {}
        self.alert_cooldown_seconds = 300.0
        self.close_grace_seconds = 2.0
        self.missing_since = {}
        self._poll_seq = 0
        self._logged_env = False

    def _log_runtime_once(self) -> None:
        """Once per process: log Python arch and process count (helps diagnose WOW64 / psutil issues)."""
        if self._logged_env:
            return
        self._logged_env = True
        try:
            arch = platform.architecture()[0]
            n_pids = len(psutil.pids())
            logger.info(
                f"[APP_ENV] python={sys.executable!r} arch={arch} "
                f"platform={platform.machine()!r} psutil={psutil.__version__} "
                f"pids_enumerated={n_pids}"
            )
            if arch == "32bit":
                logger.warning(
                    "[APP_ENV] 32-bit Python on Windows can miss or mis-label 64-bit processes. "
                    "Install 64-bit Python and reinstall the scheduled task so Notepad++/Office/VS Code are visible."
                )
        except Exception as e:
            logger.error(f"[APP_ENV] diagnostic log failed: {e}")

    def poll(self):
        """
        Scan running processes once, emit OPEN for new PIDs, CLOSE for exited PIDs,
        and update peak CPU/RAM for active tracked processes.
        """
        self._poll_seq += 1
        self._log_runtime_once()

        current_pids = set()
        now = time.time()
        ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now))
        proc_seen = 0
        tracked_scan_hits = 0

        if APP_TRACKING_DEBUG_VERBOSE:
            logger.info(
                f"[APP_POLL] cycle={self._poll_seq} ts={ts_iso} "
                f"active_tracked_pids={len(self.active_processes)}"
            )

        for pid, name, p in iter_pid_exe_name_process():
            proc_seen += 1
            try:

                if APP_TRACKING_LOG_ALL_PROCESSES:
                    logger.info(
                        f"[APP_PROC] Detected process {name} PID {pid} ts={ts_iso}"
                    )

                canonical = resolve_tracked_app(name)
                if canonical is None:
                    continue

                tracked_scan_hits += 1
                if APP_TRACKING_DEBUG_VERBOSE:
                    logger.info(
                        f"[APP_MATCH] matched tracked={canonical!r} process={name!r} "
                        f"pid={pid} ts={ts_iso}"
                    )

                current_pids.add(pid)
                self.missing_since.pop(pid, None)

                if pid in self.active_processes:
                    if APP_TRACKING_DEBUG_VERBOSE:
                        logger.info(
                            f"Duplicate APP_OPEN prevented for PID {pid} ({canonical})"
                        )
                    tracked = self.active_processes[pid]
                    try:
                        cpu = p.cpu_percent(interval=None)
                        ram_mb = p.memory_info().rss / (1024 * 1024)
                        if cpu > tracked["peak_cpu"]:
                            tracked["peak_cpu"] = cpu
                        if ram_mb > tracked["peak_ram_mb"]:
                            tracked["peak_ram_mb"] = ram_mb

                        if ram_mb >= APP_HIGH_MEMORY_MB and not tracked["high_memory_alerted"]:
                            log_event(
                                event_type="AppBehaviour",
                                user_action="APP_HIGH_MEMORY",
                                app_name=tracked["app_name"],
                                metadata={
                                    "process_name": tracked["process_name"],
                                    "pid": pid,
                                    "memoryUsage": round(ram_mb, 2),
                                },
                            )
                            tracked["high_memory_alerted"] = True

                        if cpu >= APP_HIGH_BATTERY_CPU_PERCENT and not tracked["high_battery_alerted"]:
                            # Cooldown by app (not PID) to avoid repeated alerts for multi-process browsers.
                            alert_key = f"{tracked['app_name']}:APP_HIGH_BATTERY"
                            last_sent = self.alert_cache.get(alert_key, 0)
                            if (now - last_sent) >= self.alert_cooldown_seconds:
                                log_event(
                                    event_type="AppBehaviour",
                                    user_action="APP_HIGH_BATTERY",
                                    app_name=tracked["app_name"],
                                    metadata={
                                        "process_name": tracked["process_name"],
                                    "pid": pid,
                                },
                                )
                                tracked["high_battery_alerted"] = True
                                self.alert_cache[alert_key] = now
                    except Exception as ex:
                        logger.error(
                            f"[APP_TRACK] peak stats error PID={pid} name={name!r}: {ex}\n"
                            f"{traceback.format_exc()}"
                        )
                    continue

                # Check if this application is ALREADY tracked by ANOTHER PID
                app_already_open = any(v["app_name"] == canonical for v in self.active_processes.values())

                if not app_already_open:
                    if APP_TRACKING_DEBUG_VERBOSE:
                        logger.info(
                            f"APP_OPEN generated for {canonical} (First PID {pid}) process_name={name!r} ts={ts_iso}"
                        )

                    log_event(
                        event_type="AppBehaviour",
                        user_action="OPEN",
                        app_name=canonical,
                        metadata={
                            "process_name": name,
                            "pid": pid,
                            "openTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
                        },
                    )

                try:
                    p.cpu_percent()
                except Exception as ex:
                    logger.error(f"[APP_OPEN] cpu_percent seed failed PID={pid}: {ex}")

                self.active_processes[pid] = {
                    "app_name": canonical,
                    "process_name": name,
                    "start_time": now,
                    "peak_cpu": 0.0,
                    "peak_ram_mb": 0.0,
                    "high_memory_alerted": False,
                    "high_battery_alerted": False,
                }

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.error(
                    f"[APP_POLL] unexpected error in process loop pid={pid} name={name!r}: {e}\n"
                    f"{traceback.format_exc()}"
                )

        if APP_TRACKING_DEBUG_VERBOSE:
            logger.info(
                f"[APP_POLL] cycle={self._poll_seq} end ts={ts_iso} "
                f"processes_scanned={proc_seen} tracked_matches_this_scan={tracked_scan_hits} "
                f"active_tracked_pids={len(self.active_processes)}"
            )

        closed_pids = set(self.active_processes.keys()) - current_pids
        for pid in closed_pids:
            first_missing_at = self.missing_since.get(pid)
            if first_missing_at is None:
                self.missing_since[pid] = now
                continue
            if (now - first_missing_at) < self.close_grace_seconds:
                continue

            tracked = self.active_processes[pid]
            app_name = tracked["app_name"]
            duration = now - tracked["start_time"]

            # Remove from active first
            del self.active_processes[pid]
            self.missing_since.pop(pid, None)

            # Check if any OTHER PID of the same app is still active
            app_still_open = any(v["app_name"] == app_name for v in self.active_processes.values())

            if not app_still_open:
                if APP_TRACKING_DEBUG_VERBOSE:
                    logger.info(
                        f"APP_CLOSE generated for {app_name} (Last PID {pid}) "
                        f"duration {duration:.0f}s process_name={tracked['process_name']!r} ts={ts_iso}"
                    )

                log_event(
                    event_type="AppBehaviour",
                    user_action="CLOSE",
                    app_name=app_name,
                    metadata={
                        "process_name": tracked["process_name"],
                        "openTimestamp": time.strftime(
                            "%Y-%m-%dT%H:%M:%S%z", time.localtime(tracked["start_time"])
                        ),
                        "closeTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
                        "sessionDuration": round(duration, 2),
                        "peak_cpu": round(tracked["peak_cpu"], 2),
                        "peak_ram_mb": round(tracked["peak_ram_mb"], 2),
                        "pid": pid,
                        "force_closed": None,
                    },
                )
