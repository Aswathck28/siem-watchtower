"""
Hidden Win32 window: receives WTS session and power notifications for login/lock/sleep/shutdown.
"""
import time

import win32api
import win32con
import win32gui
import win32ts
import threading
from utils.db_queue import log_event
from utils.agent_logger import logger
from utils.state_store import set_state
from datetime import datetime

# Windows Session Hooks Constants
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOGON = 0x5
WTS_SESSION_LOGOFF = 0x6
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8
WM_POWERBROADCAST = 0x021B
WM_ENDSESSION = 0x0016

class WindowsEventHandler:
    """Registers a message-only window and pumps messages for session/power events."""

    def __init__(self):
        self.hwnd = None
        # Windows can deliver the same session notification multiple times in quick succession.
        self._last_session_emit = {}  # wparam -> monotonic time
        self._session_debounce_sec = 3.0

    def wndproc(self, hwnd, msg, wparam, lparam):
        """Win32 window procedure: translate session/power messages into log_event calls."""
        try:
            if msg == WM_WTSSESSION_CHANGE:
                now = time.monotonic()
                last = self._last_session_emit.get(wparam)
                if last is not None and (now - last) < self._session_debounce_sec:
                    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
                self._last_session_emit[wparam] = now

                if wparam == WTS_SESSION_LOCK:
                    # Single lock event (SESSION_LOCK dropped — duplicate of SCREEN_LOCKED for SIEM).
                    log_event("Authentication", "SCREEN_LOCKED")
                elif wparam == WTS_SESSION_UNLOCK:
                    log_event("Authentication", "SCREEN_UNLOCKED")
                elif wparam == WTS_SESSION_LOGON:
                    log_event("Authentication", "USER_LOGIN")
                elif wparam == WTS_SESSION_LOGOFF:
                    log_event("Authentication", "USER_LOGOUT")
            
            elif msg == WM_POWERBROADCAST:
                PBT_APMSUSPEND = 0x0004
                PBT_APMRESUMEAUTOMATIC = 0x0012
                if wparam == PBT_APMSUSPEND:
                    log_event("SystemPerformance", "SYSTEM_SLEEP")
                elif wparam == PBT_APMRESUMEAUTOMATIC:
                    log_event("SystemPerformance", "SYSTEM_WAKEUP")
            elif msg == WM_ENDSESSION and wparam == 1:
                try:
                    set_state("last_shutdown_iso", datetime.now().astimezone().isoformat())
                except Exception:
                    pass
                log_event("SystemPerformance", "SYSTEM_SHUTDOWN")
        except Exception as e:
            logger.error(f"Error in wndproc processing message: {e}")

        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def _message_loop(self):
        """Register window class, create hidden HWND, WTSRegisterSessionNotification, PumpMessages."""
        try:
            hinst = win32api.GetModuleHandle(None)
            wndclass = win32gui.WNDCLASS()
            wndclass.hInstance = hinst
            wndclass.lpszClassName = "WatchtowerAgentEventHookClass"
            wndclass.lpfnWndProc = self.wndproc
            win32gui.RegisterClass(wndclass)

            # Create an invisible window purely for receiving messages
            self.hwnd = win32gui.CreateWindowEx(
                0, wndclass.lpszClassName, "WatchtowerAgentMonitor",
                0, 0, 0, win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT,
                0, 0, hinst, None
            )

            # Register for session notifications
            win32ts.WTSRegisterSessionNotification(self.hwnd, win32ts.NOTIFY_FOR_ALL_SESSIONS)
            logger.info("Windows event hooks (Login/Lock/Sleep) registered successfully.")
            
            # Start pumping messages
            win32gui.PumpMessages()
        except Exception as e:
            logger.error(f"Windows Event loop error: {e}")

    def start_in_bg(self):
        """Start the Win32 message loop on a daemon thread."""
        t = threading.Thread(target=self._message_loop, daemon=True)
        t.start()

    def stop(self):
        """Unregister WTS notifications and post WM_CLOSE to the hidden window."""
        if self.hwnd:
            try:
                win32ts.WTSUnRegisterSessionNotification(self.hwnd)
                win32gui.PostMessage(self.hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception as e:
                logger.error(f"Error stopping Windows Event handler: {e}")
