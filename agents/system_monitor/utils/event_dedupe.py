"""
Backward-compatible entry point for log deduplication.

Implementation lives in :mod:`utils.deduplication`; this module re-exports the same
symbols so existing ``from utils.event_dedupe import ...`` imports keep working.
"""
from utils.deduplication import (
    cooldown_for,
    emit_duplicate_log,
    fingerprint_for_event,
    should_emit,
)

__all__ = [
    "cooldown_for",
    "emit_duplicate_log",
    "fingerprint_for_event",
    "should_emit",
]
