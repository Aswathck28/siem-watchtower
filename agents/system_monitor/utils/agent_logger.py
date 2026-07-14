"""
Rotating file logger for the system monitor (agent_debug.log).
"""
import logging
from logging.handlers import RotatingFileHandler

from config import LOG_PATH


class FlushingRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that flushes after each record so viewers see new lines immediately."""

    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logger():
    """Configure the SystemMonitor logger with a rotating file handler and DEBUG level."""
    handler = FlushingRotatingFileHandler(LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=3)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)

    log = logging.getLogger("SystemMonitor")
    log.setLevel(logging.DEBUG)

    if not log.handlers:
        log.addHandler(handler)

    return log


logger = setup_logger()
