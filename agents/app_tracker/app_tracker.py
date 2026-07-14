import atexit
import ctypes
import json
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import psutil

# --- CONFIGURATION ---
SERVER_URL = "http://localhost:5000/api/agent/log"
POLL_INTERVAL_SECONDS = 1.0   # Set to 1.0s for real-time responsiveness without excess CPU
HID_CHECK_INTERVAL    = 10    # Throttled (e.g. every 20s)
USER_ID  = "123456"
HOSTNAME = socket.gethostname()

# Required process list (lowercased)
TARGET_PROCS = {
    "notepad.exe",
    "notepad++.exe",
    "excel.exe",
    "winword.exe",
    "chrome.exe",
    "msedge.exe",
    "code.exe",
    "codeblocks.exe",
    "pgadmin4.exe",
    "cmd.exe",
}

# Local deduplication to prevent spamming the server
last_sent_cache = {} # { event_key: timestamp }

# Function: is_locally_deduped
# Description: Checks if an event for a specific application was sent within a defined time window
#              to prevent redundant telemetry from flooding the server.
# Parameters:
#   - event_type (str): The type of event (e.g., 'OPEN', 'CLOSE', 'HIGH_CPU_LOAD').
#   - app_name (str): The name of the application associated with the event (optional).
#   - window (int): The time window in seconds within which to suppress duplicates. Defaults to 5.
# Returns:
#   - bool: True if the event is a duplicate within the window, False otherwise.
def is_locally_deduped(event_type: str, app_name: str = "", window: int = 5) -> bool:
    key = f"{event_type}:{app_name}"
    now = time.time()
    if key in last_sent_cache and (now - last_sent_cache[key]) < window:
        return True
    last_sent_cache[key] = now
    return False

# Function: iso_timestamp
# Description: Generates a current local timestamp formatted as an ISO-8601 string with timezone offset.
# Parameters:
#   - None
# Returns:
#   - str: A string representing the current ISO-8601 timestamp.
def iso_timestamp() -> str:
    return datetime.now().astimezone().isoformat()

# Function: build_elite_payload
# Description: Constructs a standardized dictionary payload containing telemetry data, 
#              user identification, and system metadata for the SIEM backend.
# Parameters:
#   - event_type (str): The high-level category of the event.
#   - user_action (str): The specific action or state change occurring.
#   - app_name (str): The name of the target application (optional).
#   - severity (str): The urgency level (e.g., 'INFO', 'WARN', 'CRITICAL'). Defaults to 'INFO'.
#   - metadata (dict): Additional key-value pairs for context (optional).
# Returns:
#   - dict: A dictionary prepared for JSON serialization and backend ingestion.
def build_elite_payload(event_type: str, user_action: str, app_name: str = "",
                         severity: str = "INFO", metadata: dict = None) -> dict:
    return {
        "timestamp": iso_timestamp(),
        "event_type": event_type,
        "user_action": user_action,
        "application_name": app_name,
        "severity": severity,
        "source": "WATCHTOWER_AGENT",
        "user_id": USER_ID,
        "hostname": HOSTNAME,
        "metadata": metadata or {}
    }

# Function: post_with_retry
# Description: Sends a logging payload to the server via HTTP POST. Includes a local 
#              deduplication check for noisy events and a minimal retry mechanism for reliability.
# Parameters:
#   - url (str): The target backend endpoint.
#   - payload (dict): The telemetry data dictionary to send.
#   - max_attempts (int): Maximum number of retry attempts on network failure. Defaults to 2.
# Returns:
#   - bool: True if the log was successfully sent or deduped, False if all retry attempts failed.
def post_with_retry(url: str, payload: dict, max_attempts: int = 2) -> bool:
    """Send payload with minimal retry to keep loop fast."""
    # Local Dedupe Check for specific noisy events
    act = payload.get("user_action")
    app = payload.get("application_name", "")
    
    window = 10
    if act == "HIGH_CPU_LOAD":
        window = 300 # Wait 5 minutes between sending repeated high CPU alerts
    
    if act in ["OPEN", "CLOSE", "HIGH_CPU_LOAD", "SCREEN_LOCKED", "SCREEN_UNLOCKED", "BATTERY_CRITICAL", "CHARGER_PLUGGED_IN", "CHARGER_UNPLUGGED"]:
        if is_locally_deduped(act, app, window=window):
            return True # Pretend success, it's a duplicate

    for attempt in range(1, max_attempts + 1):
        try:
            print(f"[DEBUG] Sending log... {act} ({app})")
            data = json.dumps(payload).encode("utf-8")
            req = Request(url=url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=3) as resp:
                if 200 <= getattr(resp, "status", 200) < 300:
                    return True
        except Exception as e:
            print(f"[DEBUG] Send error: {e}")
        time.sleep(1.0)
    return False

# Function: snapshot_target_process_counts
# Description: Scans all running processes and counts instances of applications 
#              defined in the TARGET_PROCS monitoring list.
# Parameters:
#   - None
# Returns:
#   - Dict[str, int]: A dictionary mapping lowercase process names to their current running count.
def snapshot_target_process_counts() -> Dict[str, int]:
    counts = {name: 0 for name in TARGET_PROCS}
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in counts: counts[name] += 1
        except: continue
    return counts

# Function: is_workstation_locked
# Description: Determines if the Windows workstation is currently locked using two methods:
#              checking desktop input access and identifying if LogonUI.exe is in the foreground.
# Parameters:
#   - None
# Returns:
#   - bool: True if the system appears to be locked, False otherwise.
def is_workstation_locked() -> bool:
    """Detect lock state by combining Desktop access and Foreground Window checks."""
    try:
        # Method 1: Desktop Access (Reliable for session-based locking)
        hdesk = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)
        if not hdesk: return True
        ctypes.windll.user32.CloseDesktop(hdesk)

        # Method 2: Foreground Process (Reliable for modern Windows 'LogonUI.exe')
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if hwnd == 0: return True # Could be transition or lock
        
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        foreground_proc = psutil.Process(pid.value).name().lower()
        if foreground_proc == "logonui.exe": return True
        
        return False
    except:
        return False

# Function: snapshot_usb_mounts
# Description: Identifies currently mounted disk partitions that represent removable 
#              storage devices (typically drive letters like E:\ or F:\).
# Parameters:
#   - None
# Returns:
#   - Set[str]: A set of unique mountpoint strings (e.g., {'E:'}).
def snapshot_usb_mounts() -> Set[str]:
    mounts = set()
    try:
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint and ":" in part.mountpoint: mounts.add(part.mountpoint)
    except: pass
    return mounts

# Function: snapshot_hid_usb_devices
# Description: Executes a PowerShell command to detect present HID-class USB devices 
#              (keyboards, mice, receivers) and returns their unique Instance IDs.
# Parameters:
#   - None
# Returns:
#   - Optional[Set[str]]: A set of HID Instance IDs, or None if the detection command fails.
def snapshot_hid_usb_devices() -> Optional[Set[str]]:
    devices = set()
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB*' -and ($_.Class -like '*HID*' -or $_.FriendlyName -match 'Mouse|Receiver|Dongle|Keyboard') } | Select-Object -ExpandProperty InstanceId"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=5)
        for line in out.splitlines():
            if line.strip(): devices.add(line.strip())
    except: return None
    return devices

# Function: get_battery_status
# Description: Polls system hardware sensors to retrieve the current battery percentage 
#              and charging status. Uses Windows PowerShell for accurate Windows-reported values.
# Parameters:
#   - None
# Returns:
#   - Optional[dict]: A dictionary with 'percent' (float) and 'charging' (bool), or None if unavailable.
def get_battery_status() -> Optional[dict]:
    try:
        bat = psutil.sensors_battery()
        if not bat: return None
        return {"percent": round(bat.percent, 1), "charging": bool(bat.power_plugged)}
    except:
        return None

# Function: detect_high_usage
# Description: Triggers a momentary block to identify the highest CPU consuming process.
#              This is designed to only be called when the total system CPU load is critically high.
# Parameters:
#   - None
# Returns:
#   - Tuple[str, float]: A tuple containing (process_name, cpu_percentage).
def detect_high_usage() -> Tuple[str, float]:
    top_name, top_cpu = "", 0.0
    try:
        procs = list(psutil.process_iter(["name"]))
        # Seed the cpu_percent
        for p in procs:
            try: p.cpu_percent(None)
            except: pass
        
        # Sample over 0.2 seconds
        time.sleep(0.2)
        
        for p in procs:
            try:
                cpu = p.cpu_percent(None)
                name = (p.info.get("name") or "").lower()
                # Ignore safe/idle system processes
                if name == "system idle process" or "idle" in name:
                    continue
                if cpu > top_cpu: 
                    top_name, top_cpu = name, cpu
            except: continue
    except: pass
    return top_name, top_cpu

def get_foreground_window_title() -> str:
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value
    except:
        return ""

def clean_browser_title(title: str) -> str:
    if not title:
        return ""
    # Split by dash and remove the browser name at the end
    parts = [p.strip() for p in title.split(" - ")]
    if len(parts) > 1:
        # Exclude common browser suffixes
        if parts[-1].lower() in ["google chrome", "microsoft edge", "mozilla firefox", "opera", "brave"]:
            parts.pop()
    return " - ".join(parts)

# Function: run_agent
# Description: The primary infinite execution loop. It continuously monitors the system 
#              for application activity, screen locks, hardware changes, and performance 
#              spikes, reporting events to the SIEM backend at set intervals.
# Parameters:
#   - None
# Returns:
#   - None: Runs indefinitely until terminated.
def run_agent() -> None:
    print(f"[DEBUG] Agent running on {HOSTNAME} (User: {USER_ID})")
    
    # Init state
    proc_state = snapshot_target_process_counts()
    locked_state = is_workstation_locked()
    usb_state = snapshot_usb_mounts()
    dongle_state = snapshot_hid_usb_devices() or set()
    battery_state = get_battery_status()
    last_title = ""
    hid_counter = 0

    # Startup event
    post_with_retry(SERVER_URL, build_elite_payload("SystemPerformance", "SYSTEM_STARTUP"))

    # Register exit event
    def on_exit():
        print("[DEBUG] Agent terminating / System Shutdown")
        post_with_retry(SERVER_URL, build_elite_payload("SystemPerformance", "SYSTEM_SHUTDOWN"))
        
    atexit.register(on_exit)

    # Clear previous CPU reading context
    psutil.cpu_percent(interval=None)

    while True:
        try:
            # 1) App Detection (Scanned every 5.0 seconds to keep CPU near 0%)
            if not hasattr(run_agent, '_last_proc_scan'):
                run_agent._last_proc_scan = 0
            if time.time() - run_agent._last_proc_scan >= 5.0:
                run_agent._last_proc_scan = time.time()
                curr_procs = snapshot_target_process_counts()
                for app in TARGET_PROCS:
                    prev, now = proc_state.get(app, 0), curr_procs.get(app, 0)
                    if prev == 0 and now > 0:
                        print(f"[DEBUG] App Opened: {app}")
                        post_with_retry(SERVER_URL, build_elite_payload("AppBehaviour", "OPEN", app_name=app))
                    elif prev > 0 and now == 0:
                        print(f"[DEBUG] App Closed: {app}")
                        post_with_retry(SERVER_URL, build_elite_payload("AppBehaviour", "CLOSE", app_name=app))
                proc_state = curr_procs

            # 2) Lock Detection
            curr_lock = is_workstation_locked()
            if curr_lock != locked_state:
                locked_state = curr_lock
                act = "SCREEN_LOCKED" if curr_lock else "SCREEN_UNLOCKED"
                print(f"[DEBUG] {act}")
                post_with_retry(SERVER_URL, build_elite_payload("Authentication", act))

            # 3) Devices
            curr_usb = snapshot_usb_mounts()
            for mt in (curr_usb - usb_state): post_with_retry(SERVER_URL, build_elite_payload("DeviceControl", "USB_INSERTED", metadata={"mount": mt}))
            for mt in (usb_state - curr_usb): post_with_retry(SERVER_URL, build_elite_payload("DeviceControl", "USB_REMOVED", metadata={"mount": mt}))
            usb_state = curr_usb

            # 4) Battery
            curr_bat = get_battery_status()
            if curr_bat and battery_state:
                # Send battery status on charger state change WITH battery level
                if curr_bat["charging"] != battery_state["charging"]:
                    act = "CHARGER_PLUGGED_IN" if curr_bat["charging"] else "CHARGER_UNPLUGGED"
                    print(f"[DEBUG] {act}: {curr_bat['percent']}%")
                    post_with_retry(SERVER_URL, build_elite_payload("DeviceControl", act, metadata={"level": curr_bat["percent"], "percent": curr_bat["percent"], "charging": curr_bat["charging"]}))
                
                # Check for critical battery drain
                if not curr_bat["charging"] and curr_bat["percent"] <= 20 and battery_state["percent"] > 20:
                    print(f"[DEBUG] BATTERY_CRITICAL: {curr_bat['percent']}%")
                    post_with_retry(SERVER_URL, build_elite_payload("SystemPerformance", "BATTERY_CRITICAL", metadata={"level": curr_bat["percent"]}))
                
                # Send periodic battery status every 30 seconds to keep server updated (more accurate)
                if not hasattr(run_agent, '_last_battery_broadcast'):
                    run_agent._last_battery_broadcast = 0
                if time.time() - run_agent._last_battery_broadcast > 30:
                    run_agent._last_battery_broadcast = time.time()
                    post_with_retry(SERVER_URL, build_elite_payload("SystemPerformance", "BATTERY_STATUS", metadata={"level": curr_bat["percent"], "percent": curr_bat["percent"], "charging": curr_bat["charging"]}))

            battery_state = curr_bat

            # 5) Performance (Track overall, only drill down if heavily loaded)
            system_cpu = psutil.cpu_percent(interval=None)
            if system_cpu > 80.0:
                top_n, top_c = detect_high_usage()
                if top_c > 10.0: # Ensure the app itself is actually consuming significant CPU
                    post_with_retry(SERVER_URL, build_elite_payload("SystemPerformance", "HIGH_CPU_LOAD", app_name=top_n, metadata={"cpu": round(top_c, 1), "system_total": round(system_cpu, 1)}))

            # 6) Active Window / Website Focus change tracking
            curr_title = get_foreground_window_title()
            if curr_title and curr_title != last_title:
                curr_clean = clean_browser_title(curr_title)
                last_clean = clean_browser_title(last_title)
                
                # Detect if the active process is a browser
                is_browser = False
                browser_name = ""
                try:
                    hwnd = ctypes.windll.user32.GetForegroundWindow()
                    pid = ctypes.c_ulong()
                    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    proc_name = psutil.Process(pid.value).name().lower()
                    if proc_name in ["chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe"]:
                        is_browser = True
                        browser_name = proc_name.replace(".exe", "").capitalize()
                except:
                    pass
                
                if is_browser and curr_clean != last_clean:
                    # Log transition as a browser website switch
                    transition_title = f"{curr_clean} (browser switch: moved from {last_clean or 'blank/desktop'})"
                    metadata = {
                        "title": transition_title,
                        "prev_title": last_title,
                        "from_website": last_clean,
                        "to_website": curr_clean,
                        "browser": browser_name
                    }
                    print(f"[DEBUG] Website changed: {last_clean} -> {curr_clean}")
                    post_with_retry(SERVER_URL, build_elite_payload("AppBehaviour", "FOREGROUND_WINDOW_CHANGE", metadata=metadata))
                elif not is_browser:
                    # Normal window switch (non-browser application)
                    metadata = {"title": curr_title, "prev_title": last_title}
                    print(f"[DEBUG] Window changed: {curr_title}")
                    post_with_retry(SERVER_URL, build_elite_payload("AppBehaviour", "FOREGROUND_WINDOW_CHANGE", metadata=metadata))
                
                last_title = curr_title

        except Exception as e: print(f"[DEBUG] Loop error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    try: run_agent()
    except KeyboardInterrupt: print("[DEBUG] Stopped")
