import socket
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json

import psutil

# --- CONFIGURATION ---
SERVER_URL = "http://localhost:5000/api/agent/log"
POLL_INTERVAL_SECONDS = 1.5  # 1–2 second polling interval to avoid high CPU
USER_ID = "demo_user"
HOSTNAME = socket.gethostname()

# Track only these processes (case-insensitive; values stored lowercase)
TARGET_PROCS = {
    "notepad.exe",
    "notepad++.exe",
    "excel.exe",
    "msedge.exe",
    "chrome.exe",
    "codeblocks.exe",
    "code.exe",
    "idea64.exe",
}


def iso_timestamp() -> str:
    """Purpose: Generate a UTC ISO-8601 timestamp.
    Input: None.
    Output: ISO timestamp string.
    """
    return datetime.now(timezone.utc).isoformat()


def post_with_retry(url: str, payload: dict, max_attempts: int = 5, timeout_seconds: int = 5) -> bool:
    """Purpose: Send agent log payload with retry/backoff on failures.
    Input: url (str), payload (dict), max_attempts (int), timeout_seconds (int).
    Output: True on success (2xx), False otherwise.
    """
    backoff = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            print(f"[DEBUG] Sending log... attempt={attempt} payload={payload}")
            data = json.dumps(payload).encode("utf-8")
            req = Request(
                url=url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=timeout_seconds) as resp:
                status = getattr(resp, "status", 200)
                if 200 <= status < 300:
                    print(f"[DEBUG] Success sending log. status={status}")
                    return True
                body = resp.read(300).decode("utf-8", errors="replace")
                print(f"[DEBUG] Failure sending log. status={status} body={body}")
        except HTTPError as e:
            try:
                body = e.read(300).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            print(f"[DEBUG] Failure sending log. status={e.code} body={body}")
        except URLError as e:
            print(f"[DEBUG] Failure sending log. error={e}")
        except Exception as e:
            print(f"[DEBUG] Failure sending log. error={e}")

        # simple backoff with cap (keeps demo responsive)
        time.sleep(min(backoff, 5.0))
        backoff *= 1.5

    return False


def build_payload(application_name: str, event_type: str) -> dict:
    """Purpose: Build a backend-compatible agent payload.
    Input: application_name (str), event_type (str: OPEN/CLOSE).
    Output: dict payload matching required format.
    """
    return {
        "timestamp": iso_timestamp(),
        "application_name": application_name,
        "event_type": event_type,
        "user_id": USER_ID,
        "hostname": HOSTNAME,
    }


def collect_target_processes() -> dict:
    """Purpose: Snapshot currently-running target processes.
    Input: None.
    Output: dict of pid -> process_name (lowercased).
    """
    current = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            pid = proc.info.get("pid")
            if pid and name in TARGET_PROCS:
                current[pid] = name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return current


def run_agent() -> None:
    """Purpose: Run the continuous agent loop, detect OPEN/CLOSE events, and send them to backend.
    Input: None.
    Output: None.
    """
    print("[DEBUG] Agent started")
    print(f"[DEBUG] Hostname={HOSTNAME} UserId={USER_ID}")
    print(f"[DEBUG] Monitoring: {', '.join(sorted(TARGET_PROCS))}")

    # State dictionary to avoid duplicate logs: application_name -> running_instance_count
    state = {name: 0 for name in TARGET_PROCS}

    while True:
        try:
            current = collect_target_processes()

            # Count instances per application
            current_counts = {name: 0 for name in TARGET_PROCS}
            for _, name in current.items():
                if name in current_counts:
                    current_counts[name] += 1

            # Detect OPEN/CLOSE per application (0 -> >0, >0 -> 0)
            for app_name in sorted(TARGET_PROCS):
                prev_count = state.get(app_name, 0)
                now_count = current_counts.get(app_name, 0)

                if prev_count == 0 and now_count > 0:
                    state[app_name] = now_count
                    print(f"[DEBUG] Detected OPEN: name={app_name} instances={now_count}")
                    post_with_retry(SERVER_URL, build_payload(app_name, "OPEN"))
                elif prev_count > 0 and now_count == 0:
                    state[app_name] = 0
                    print(f"[DEBUG] Detected CLOSE: name={app_name}")
                    post_with_retry(SERVER_URL, build_payload(app_name, "CLOSE"))
                else:
                    state[app_name] = now_count

        except Exception as e:
            print(f"[DEBUG] Agent loop failure: {e}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        run_agent()
    except KeyboardInterrupt:
        print("[DEBUG] Agent stopped (KeyboardInterrupt)")
