"""
In-memory cooldown deduplication before SQLite enqueue.

Each candidate log is identified by a stable fingerprint (event type, action, host,
process identity). If the same fingerprint was emitted within the configured cooldown
window, the event is dropped and a short reason is returned for logging.

This module is the single source of truth for duplicate prevention; ``event_dedupe``
re-exports its API for backward compatibility.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, Optional, Tuple

from utils.agent_logger import logger

# (event_type, user_action) -> cooldown seconds. 0.0 = do not apply global dedupe.
_EVENT_COOLDOWNS: Dict[Tuple[str, str], float] = {
    ("Authentication", "USER_LOGIN"): 120.0,
    ("Authentication", "USER_LOGOUT"): 120.0,
    ("Authentication", "SCREEN_LOCKED"): 120.0,
    ("Authentication", "SCREEN_UNLOCKED"): 120.0,
    ("Authentication", "SESSION_LOCK"): 120.0,
    ("Authentication", "SESSION_UNLOCK"): 120.0,
    ("SystemPerformance", "HIGH_MEMORY_USAGE"): 300.0,
    ("SystemPerformance", "HIGH_CPU_USAGE"): 300.0,
    ("SystemPerformance", "HIGH_DISK_USAGE"): 300.0,
    ("SystemPerformance", "BATTERY_DRAIN_ALERT"): 600.0,
    ("SystemPerformance", "BATTERY_CRITICAL"): 600.0,
    ("DeviceControl", "CHARGER_PLUGGED_IN"): 30.0,
    ("DeviceControl", "CHARGER_UNPLUGGED"): 30.0,
    ("AppBehaviour", "APP_HIGH_MEMORY"): 600.0,
    ("AppBehaviour", "APP_HIGH_BATTERY"): 600.0,
    ("SystemPerformance", "APP_BATTERY_DRAIN"): 600.0,
    ("AppBehaviour", "APP_OPEN"): 120.0,
    ("AppBehaviour", "APP_CLOSE"): 120.0,
    ("AppBehaviour", "OPEN"): 120.0,
    ("AppBehaviour", "CLOSE"): 120.0,
    ("SystemPerformance", "SYSTEM_SLEEP"): 60.0,
    ("SystemPerformance", "SYSTEM_WAKEUP"): 60.0,
    ("SystemPerformance", "SYSTEM_SHUTDOWN"): 300.0,
    ("SystemPerformance", "SYSTEM_STARTUP"): 300.0,
    ("SystemPerformance", "AGENT_RUNNING"): 600.0,
    ("SystemPerformance", "SYSTEM_UPTIME_DURATION"): 600.0,
    ("SystemPerformance", "APP_TOP_CONSUMERS_REPORT"): 300.0,
    ("SystemPerformance", "IDLE_TIME_START"): 120.0,
    ("SystemPerformance", "IDLE_TIME_END"): 120.0,
}

_DEFAULT_COOLDOWN = 10.0

_lock = threading.Lock()
_last_emit_mono: Dict[str, float] = {}


def _norm_str(value: Any) -> str:
    """Return a lowercase trimmed string for stable fingerprint segments."""
    if value is None:
        return ""
    return str(value).strip().lower()


def fingerprint_for_event(
    event_type: str,
    user_action: str,
    username: str,
    hostname: str,
    app_name: str = "",
    metadata: Optional[dict] = None,
) -> Tuple[str, str]:
    """
    Build a SHA-256 fingerprint key for deduplication.

    The key combines event category, action, user, host, and optional process/PID
    from metadata so distinct processes are never merged incorrectly.

    Returns:
        A tuple ``(dedupe_key_hex, human_debug_string)``.
    """
    meta = metadata or {}
    proc = meta.get("process_name") or meta.get("processName") or app_name or ""
    pid = meta.get("pid", "")
    if pid is not None and pid != "":
        pid_s = str(int(pid)) if isinstance(pid, (int, float)) and pid == int(pid) else str(pid)
    else:
        pid_s = ""
    parts = "|".join(
        [
            _norm_str(event_type),
            _norm_str(user_action),
            _norm_str(username),
            _norm_str(hostname),
            _norm_str(proc),
            _norm_str(pid_s),
        ]
    )
    digest = hashlib.sha256(parts.encode("utf-8")).hexdigest()
    return digest, parts


def cooldown_for(event_type: str, user_action: str) -> float:
    """Return the cooldown window in seconds for an (event_type, user_action) pair."""
    return _EVENT_COOLDOWNS.get((event_type, user_action), _DEFAULT_COOLDOWN)


def should_emit(
    event_type: str,
    user_action: str,
    username: str,
    hostname: str,
    app_name: str = "",
    metadata: Optional[dict] = None,
) -> Tuple[bool, str]:
    """
    Decide whether a new event may be enqueued (not a duplicate within cooldown).

    Returns:
        ``(True, "")`` if the event should be emitted, or ``(False, reason)`` if skipped.
    """
    cd = cooldown_for(event_type, user_action)
    if cd <= 0:
        return True, ""

    key, _fp = fingerprint_for_event(event_type, user_action, username, hostname, app_name, metadata)
    now = time.monotonic()
    with _lock:
        last = _last_emit_mono.get(key)
        if last is not None and (now - last) < cd:
            msg = _duplicate_log_message(event_type, user_action, metadata)
            return False, msg
        _last_emit_mono[key] = now
        if len(_last_emit_mono) > 50_000:
            cutoff = now - 3600
            dead = [k for k, t in _last_emit_mono.items() if t < cutoff]
            for k in dead[:20_000]:
                _last_emit_mono.pop(k, None)

    return True, ""


def _duplicate_log_message(event_type: str, user_action: str, metadata: Optional[dict]) -> str:
    """Build a short human-readable reason string when an event is deduplicated."""
    meta = metadata or {}
    pid = meta.get("pid", "")
    pid_bit = f" PID {pid}" if pid != "" and pid is not None else ""

    if event_type == "Authentication" and user_action in ("USER_LOGIN", "USER_LOGOUT"):
        return f"Duplicate {user_action} prevented (cooldown)"
    if event_type == "Authentication" and user_action in (
        "SCREEN_LOCKED",
        "SCREEN_UNLOCKED",
        "SESSION_LOCK",
        "SESSION_UNLOCK",
    ):
        return f"Duplicate {user_action} prevented"
    if user_action == "HIGH_MEMORY_USAGE":
        return "Duplicate HIGH_MEMORY_USAGE prevented"
    if user_action == "HIGH_CPU_USAGE":
        return "Duplicate HIGH_CPU_USAGE prevented"
    if user_action == "HIGH_DISK_USAGE":
        return "Duplicate HIGH_DISK_USAGE prevented"
    if user_action == "BATTERY_DRAIN_ALERT":
        return "Duplicate BATTERY_DRAIN_ALERT prevented"
    if user_action == "BATTERY_CRITICAL":
        return "Duplicate LOW_BATTERY / BATTERY_CRITICAL prevented"
    if user_action == "APP_TOP_CONSUMERS_REPORT":
        return "Duplicate APP_TOP_CONSUMERS_REPORT prevented"
    if user_action in ("CHARGER_PLUGGED_IN", "CHARGER_UNPLUGGED"):
        return f"Duplicate {user_action} prevented"
    if user_action == "APP_HIGH_MEMORY":
        return f"Duplicate APP_HIGH_MEMORY prevented{pid_bit}"
    if user_action == "APP_HIGH_BATTERY":
        return f"Duplicate APP_HIGH_BATTERY prevented{pid_bit}"
    if user_action == "APP_BATTERY_DRAIN":
        return f"Duplicate APP_BATTERY_DRAIN prevented{pid_bit}"
    if event_type == "AppBehaviour" and user_action == "OPEN":
        return f"Duplicate APP_OPEN prevented{pid_bit}"
    if event_type == "AppBehaviour" and user_action == "CLOSE":
        return f"Duplicate APP_CLOSE prevented{pid_bit}"
    return f"Duplicate event prevented: {event_type}/{user_action}{pid_bit}"


def emit_duplicate_log(block_reason: str) -> None:
    """Write an informational log line when a duplicate was suppressed."""
    if block_reason:
        logger.info(f"[DEDUPE] {block_reason}")
