"""
Persistent agent state stored in SQLite (survives reboots).

This is used to remember the last shutdown time across restarts so the next startup
can compute downtime duration without relying on the server being reachable.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Optional

from config import DB_PATH
from utils.agent_logger import logger


def _connect() -> sqlite3.Connection:
    """Open a SQLite connection to the agent DB."""
    return sqlite3.connect(DB_PATH)


def _init_schema(conn: sqlite3.Connection) -> None:
    """Ensure the agent_state table exists."""
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_state (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
        """
    )
    conn.commit()


def get_state(key: str) -> Optional[str]:
    """Return the stored value for `key`, or None if missing/unreadable."""
    try:
        conn = _connect()
        _init_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT value FROM agent_state WHERE key = ? LIMIT 1", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logger.error(f"state_store.get_state failed: {e}")
        return None


def set_state(key: str, value: str) -> None:
    """Insert or update a `key` -> `value` pair with a fresh updated_at timestamp."""
    try:
        conn = _connect()
        _init_schema(conn)
        cur = conn.cursor()
        now_iso = datetime.now().astimezone().isoformat()
        cur.execute(
            """
            INSERT INTO agent_state(key, value, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """,
            (key, value, now_iso),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"state_store.set_state failed: {e}")


def compute_downtime_seconds(now_iso: str) -> Optional[int]:
    """
    Compute downtime seconds from last recorded shutdown to `now_iso`.

    Returns None if there is no prior shutdown record or timestamps cannot be parsed.
    """
    prev = get_state("last_shutdown_iso")
    if not prev:
        return None
    try:
        t0 = datetime.fromisoformat(prev)
        t1 = datetime.fromisoformat(now_iso)
        dt = t1 - t0
        secs = int(dt.total_seconds())
        return secs if secs >= 0 else None
    except Exception:
        return None

