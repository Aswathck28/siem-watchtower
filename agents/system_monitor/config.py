"""
Agent configuration: backend URL, poll intervals, debug flags, thresholds, and paths.
"""
import os
import socket

# --- NETWORK CONFIGURATION ---
# Set SIEM_BACKEND_URL if the Node server is not on localhost:5000.
BACKEND_BASE_URL = os.environ.get("SIEM_BACKEND_URL", "http://localhost:5000").rstrip("/")
SERVER_URL = f"{BACKEND_BASE_URL}/api/agent/log"
SERVER_HEALTH_URL = f"{BACKEND_BASE_URL}/api/health"
# Optional: set SIEM_REPORTING_HOSTNAME so DB + dashboard filter match (must equal users.hostname).
HOSTNAME = (os.environ.get("SIEM_REPORTING_HOSTNAME") or "").strip() or socket.gethostname()
USER_ID = "SYSTEM_AGENT"

# --- POLLING INTERVALS (Seconds) ---
# App poll: Reduced to 0.3s for absolute real-time tracking.
POLL_INTERVAL_APP = 1.0
POLL_INTERVAL_RESOURCE = 60.0
# Flush queued SQLite rows to the API immediately (0.3s) for zero delay.
POLL_INTERVAL_QUEUE = 0.3
POLL_INTERVAL_IDLE = 15.0
HEARTBEAT_INTERVAL = 600.0
# Top memory / CPU-by-process report (replaces aggregate resource “snapshot”; CPU on battery ≈ drain proxy).
TOP_APPS_REPORT_INTERVAL_SEC = 1800.0 # 30 mins
TOP_APPS_REPORT_RANK = 6
TOP_APPS_CPU_SAMPLE_SLEEP_SEC = 0.18

# --- APP TRACKING DEBUG (agent_debug.log) ---
# APP_TRACKING_LOG_ALL_PROCESSES: logs every PID each poll (~hundreds of lines/sec) — file grows fast;
# the "last" timestamp is always at the **bottom** of the file. Set True only for short debugging.
APP_TRACKING_DEBUG_VERBOSE = False
APP_TRACKING_LOG_ALL_PROCESSES = False
DEBUG_QUEUE_HTTP = False

# --- TARGET APPLICATION TRACKING ---
# Canonical display names; matching rules are in monitors.app_tracker.resolve_tracked_app (case-insensitive / partial).
TRACKED_APPS = {
    "notepad.exe": "Notepad",
    "notepad++.exe": "Notepad++",
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "code.exe": "Visual Studio Code",
    "codeblocks.exe": "CodeBlocks",
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "pgadmin4.exe": "pgAdmin 4",
}

# --- THRESHOLDS ---
RAM_HIGH_PERCENT = 90.0
DISK_HIGH_PERCENT = 90.0
CPU_HIGH_PERCENT = 85.0
BATTERY_DRAIN_THRESHOLD_PERCENT = 5.0
BATTERY_CRITICAL_PERCENT = 15.0
# Hourly drain-rate risk bands (percent charge per hour): Goal 3 dynamic risk.
BATTERY_DRAIN_RISK_LOW_MAX_PCT_PER_H = 5.0
BATTERY_DRAIN_RISK_MEDIUM_MAX_PCT_PER_H = 12.0
BATTERY_DRAIN_RISK_HIGH_MAX_PCT_PER_H = 20.0
# Rolling 1h battery analytics (samples spaced at least this many seconds).
BATTERY_HISTORY_SAMPLE_INTERVAL_SEC = 180.0
BATTERY_FAST_DRAIN_RATE_PCT_PER_H = 25.0
BATTERY_RISK_MEDIUM_DRAIN_PCT_PER_H = 12.0
BATTERY_RISK_HIGH_DRAIN_PCT_PER_H = 25.0
BATTERY_FAST_DRAIN_SHORT_WINDOW_MIN = 30.0
BATTERY_FAST_DRAIN_SHORT_DROP_PCT = 10.0
APP_HIGH_MEMORY_MB = 1024.0
APP_HIGH_BATTERY_CPU_PERCENT = 60.0
IDLE_THRESHOLD_SECONDS = 300

# --- FILE PATHS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "offline_logs.sqlite")
LOG_PATH = os.path.join(BASE_DIR, "agent_debug.log")
