"""
Idle start/end detection using GetLastInputInfo vs GetTickCount.
"""
import ctypes
import time

from config import IDLE_THRESHOLD_SECONDS
from utils.db_queue import log_event
from utils.agent_logger import logger


class LASTINPUTINFO(ctypes.Structure):
    """Win32 LASTINPUTINFO struct for GetLastInputInfo."""

    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def _get_idle_seconds() -> int:
    """Return seconds since last keyboard/mouse input (approximate)."""
    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)) == 0:
        return 0
    millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
    return int(millis / 1000)


class IdleMonitor:
    """Emits IDLE_TIME_START / IDLE_TIME_END when crossing IDLE_THRESHOLD_SECONDS."""

    def __init__(self):
        self.is_idle = False
        self.idle_started_at = None

    def poll(self):
        """Evaluate idle duration once; emit transitions when thresholds are crossed."""
        try:
            idle_seconds = _get_idle_seconds()
            if not self.is_idle and idle_seconds >= IDLE_THRESHOLD_SECONDS:
                self.is_idle = True
                self.idle_started_at = time.time()
                log_event(
                    event_type="SystemPerformance",
                    user_action="IDLE_TIME_START",
                    metadata={"idleSeconds": idle_seconds},
                )
            elif self.is_idle and idle_seconds < 5:
                idle_duration = 0
                if self.idle_started_at is not None:
                    idle_duration = int(time.time() - self.idle_started_at)
                self.is_idle = False
                self.idle_started_at = None
                log_event(
                    event_type="SystemPerformance",
                    user_action="IDLE_TIME_END",
                    metadata={"idleDurationSeconds": idle_duration},
                )
        except Exception as e:
            logger.error(f"Idle monitor error: {e}")
