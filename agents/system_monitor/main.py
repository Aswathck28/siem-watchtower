"""
SIEM-Watchtower system monitor entrypoint: threads for app tracking, resources,
idle detection, heartbeat, Windows session hooks, and SQLite log flush.
"""
import time
import threading
import sys
import psutil
import traceback
import atexit
import signal
from datetime import datetime

from config import POLL_INTERVAL_APP, POLL_INTERVAL_RESOURCE, POLL_INTERVAL_IDLE, HEARTBEAT_INTERVAL, LOG_PATH
from utils.agent_logger import logger
from utils.db_queue import log_event, queue_worker, db_queue, probe_backend
from utils.state_store import compute_downtime_seconds, set_state
from monitors.app_tracker import AppTracker
from monitors.resource_monitor import ResourceMonitor
from monitors.windows_events import WindowsEventHandler
from monitors.idle_monitor import IdleMonitor


def run_app_monitor(tracker):
    """Loop: call AppTracker.poll() on POLL_INTERVAL_APP seconds; log crashes."""
    logger.info(f"Started AppTracker polling every {POLL_INTERVAL_APP}s")
    while True:
        try:
            tracker.poll()
        except Exception:
            logger.error(f"App Tracker Crashed: {traceback.format_exc()}")
        time.sleep(POLL_INTERVAL_APP)


def run_resource_monitor(monitor):
    """Loop: call ResourceMonitor.poll() on POLL_INTERVAL_RESOURCE seconds."""
    logger.info(f"Started ResourceMonitor polling every {POLL_INTERVAL_RESOURCE}s")
    while True:
        try:
            monitor.poll()
        except Exception:
            logger.error(f"Resource Monitor Crashed: {traceback.format_exc()}")
        time.sleep(POLL_INTERVAL_RESOURCE)


def run_heartbeat():
    """Loop: emit AGENT_RUNNING on HEARTBEAT_INTERVAL (CPU/uptime live metrics are shown on the dashboard)."""
    agent_uptime_start = time.time()
    logger.info(f"Started Heartbeat every {HEARTBEAT_INTERVAL}s")
    while True:
        try:
            agent_uptime = time.time() - agent_uptime_start
            sys_uptime = time.time() - psutil.boot_time()
            log_event(
                "SystemPerformance",
                "AGENT_RUNNING",
                metadata={
                    "agentUptimeSeconds": int(agent_uptime),
                    "systemUptimeSeconds": int(sys_uptime),
                },
            )
        except Exception as e:
            logger.error(f"Heartbeat Error: {e}")
        time.sleep(HEARTBEAT_INTERVAL)


def run_idle_monitor(monitor):
    """Loop: call IdleMonitor.poll() on POLL_INTERVAL_IDLE seconds."""
    logger.info(f"Started IdleMonitor polling every {POLL_INTERVAL_IDLE}s")
    while True:
        try:
            monitor.poll()
        except Exception:
            logger.error(f"Idle Monitor Crashed: {traceback.format_exc()}")
        time.sleep(POLL_INTERVAL_IDLE)


def main():
    """Initialize monitors, start background threads, and block forever."""
    logger.info("Initializing SIEM-Watchtower Persistent Agent...")

    try:
        now_iso = datetime.now().astimezone().isoformat()
        downtime = compute_downtime_seconds(now_iso)
        meta = {"event": "Agent Initialized"}
        if downtime is not None:
            meta["downtimeSeconds"] = downtime
        log_event("SystemPerformance", "SYSTEM_STARTUP", metadata=meta)
        set_state("last_startup_iso", now_iso)
        if (time.time() - psutil.boot_time()) < 300:
            log_event("SystemPerformance", "SYSTEM_RESTART", metadata={"event": "System boot detected recently"})
        probe_backend()
        db_queue.flush_queue()

        t_queue = threading.Thread(target=queue_worker, daemon=True)
        t_queue.start()

        win_hooks = WindowsEventHandler()
        win_hooks.start_in_bg()

        app_tracker = AppTracker()
        res_monitor = ResourceMonitor()
        idle_monitor = IdleMonitor()

        t_app = threading.Thread(target=run_app_monitor, args=(app_tracker,), daemon=True)
        t_res = threading.Thread(target=run_resource_monitor, args=(res_monitor,), daemon=True)
        t_heart = threading.Thread(target=run_heartbeat, daemon=True)
        t_idle = threading.Thread(target=run_idle_monitor, args=(idle_monitor,), daemon=True)

        t_app.start()
        t_res.start()
        t_heart.start()
        t_idle.start()

        logger.info("All subsystem monitors securely started. Agent is now active 24x7.")

        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        logger.info("Agent shutting down manually (KeyboardInterrupt).")
        try:
            set_state("last_shutdown_iso", datetime.now().astimezone().isoformat())
        except Exception:
            pass
        log_event("SystemPerformance", "SYSTEM_SHUTDOWN", metadata={"event": "Agent Terminated via SIGINT"})
        if "win_hooks" in locals():
            win_hooks.stop()
        db_queue.flush_queue()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"FATAL: Main thread crashed! {traceback.format_exc()}")
        log_event("SystemPerformance", "AGENT_CRASH", metadata={"error": str(e)[:100]})
        raise


if __name__ == "__main__":
    import win32api
    import win32event
    import winerror

    mutex = win32event.CreateMutex(None, 1, "Global\\SIEM_Watchtower_Agent_Mutex")
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        # Second copy exits silently with pythonw; log so upgrades/debugging are not confusing.
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as mf:
                mf.write(
                    f"{datetime.now().isoformat()} [SIEM_AGENT] Exiting: another instance already holds "
                    f"Global\\\\SIEM_Watchtower_Agent_Mutex (scheduled task may be running old code if you expected updates).\n"
                )
        except Exception:
            pass
        sys.exit(0)

    def _record_shutdown_state() -> None:
        """Persist last shutdown time for downtime computation on next boot."""
        try:
            set_state("last_shutdown_iso", datetime.now().astimezone().isoformat())
        except Exception:
            pass

    atexit.register(_record_shutdown_state)
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    except Exception:
        pass

    while True:
        try:
            main()
        except Exception as e:
            logger.critical(f"Agent master restart triggered due to: {e}")
            time.sleep(10)
