"""
SQLite-backed offline queue and HTTP flush to the SIEM backend /api/agent/log.
"""
import sqlite3
import json
import time
import requests
import threading
import hashlib
import getpass
from datetime import datetime

from utils.event_dedupe import emit_duplicate_log, should_emit
from config import (
    BACKEND_BASE_URL,
    DB_PATH,
    SERVER_URL,
    SERVER_HEALTH_URL,
    POLL_INTERVAL_QUEUE,
    HOSTNAME,
    USER_ID,
    DEBUG_QUEUE_HTTP,
)
from utils.agent_logger import logger


class LogQueue:
    """Persistent FIFO queue of JSON payloads with optional deduplication by content hash."""

    def __init__(self):
        self.lock = threading.Lock()
        self.init_db()

    def init_db(self):
        """Create offline_logs table, indexes, size-limit trigger, and migrate legacy columns."""
        with self.lock:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS offline_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_hash TEXT UNIQUE,
                        payload TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
                c.execute("CREATE INDEX IF NOT EXISTS idx_offline_logs_timestamp ON offline_logs(timestamp)")
                try:
                    c.execute("ALTER TABLE offline_logs ADD COLUMN event_hash TEXT")
                except Exception as alter_err:
                    if "duplicate column name" not in str(alter_err).lower():
                        raise
                c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_offline_logs_event_hash ON offline_logs(event_hash)")
                c.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS limit_logs
                    AFTER INSERT ON offline_logs
                    WHEN (SELECT COUNT(*) FROM offline_logs) > 100000
                    BEGIN
                        DELETE FROM offline_logs WHERE id IN (SELECT id FROM offline_logs ORDER BY id ASC LIMIT 10000);
                    END;
                """
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Failed to initialize SQLite offline queue: {e}")

    def _event_hash(self, payload: dict) -> str:
        """Return a stable SHA-256 hex digest of the JSON payload for deduplication."""
        stable_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(stable_json.encode("utf-8")).hexdigest()

    def enqueue(self, payload: dict):
        """Serialize payload to SQLite; uses INSERT OR IGNORE when the same hash already exists."""
        try:
            with self.lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                payload_json = json.dumps(payload)
                event_hash = self._event_hash(payload)
                c.execute(
                    "INSERT OR IGNORE INTO offline_logs (event_hash, payload) VALUES (?, ?)",
                    (event_hash, payload_json),
                )
                rowcount = c.rowcount
                conn.commit()
                conn.close()
                if rowcount > 0:
                    queue_notify.set()
                if DEBUG_QUEUE_HTTP:
                    ua = payload.get("user_action", "")
                    app = payload.get("application_name", "")
                    logger.info(
                        f"[QUEUE] enqueue hash={event_hash[:12]}... "
                        f"user_action={ua!r} application_name={app!r} "
                        f"inserted={'yes' if rowcount else 'duplicate_or_ignored'}"
                    )
        except Exception as e:
            logger.error(f"[QUEUE] Failed to enqueue log: {e}")

    def flush_queue(self):
        """POST up to 50 pending rows to SERVER_URL; delete rows on success; stop batch on network/5xx."""
        try:
            with self.lock:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT id, payload FROM offline_logs ORDER BY id ASC LIMIT 50")
                rows = c.fetchall()

                if not rows:
                    conn.close()
                    return

                ids_to_delete = []
                for row_id, payload_str in rows:
                    try:
                        payload = json.loads(payload_str)
                        if DEBUG_QUEUE_HTTP:
                            logger.info(
                                f"[QUEUE_HTTP] POST attempt id={row_id} url={SERVER_URL} "
                                f"action={payload.get('user_action')!r}"
                            )
                        response = requests.post(SERVER_URL, json=payload, timeout=5)
                        ok = response.status_code < 300
                        snippet = ""
                        try:
                            snippet = (response.text or "")[:400]
                        except Exception:
                            pass
                        if DEBUG_QUEUE_HTTP:
                            logger.info(
                                f"[QUEUE_HTTP] response id={row_id} status={response.status_code} "
                                f"ok={ok} body_snippet={snippet!r}"
                            )
                        if ok:
                            ids_to_delete.append(row_id)
                        else:
                            logger.warning(
                                f"Failed to send log to backend, stored locally (id={row_id} "
                                f"status={response.status_code} action={payload.get('user_action')!r}): {snippet}"
                            )
                            if response.status_code >= 500:
                                break
                            elif response.status_code == 400:
                                ids_to_delete.append(row_id)
                    except requests.RequestException as ex:
                        logger.warning(
                            f"Failed to send log to backend, stored locally (id={row_id}): {ex}"
                        )
                        break

                if ids_to_delete:
                    id_placeholders = ",".join("?" * len(ids_to_delete))
                    c.execute(f"DELETE FROM offline_logs WHERE id IN ({id_placeholders})", ids_to_delete)
                    conn.commit()
                    if DEBUG_QUEUE_HTTP:
                        logger.info(f"Successfully sent batch of {len(ids_to_delete)} logs to backend.")

                conn.close()
        except Exception as e:
            logger.error(f"Error during queue flush: {e}")


queue_notify = threading.Event()
db_queue = LogQueue()


def iso_timestamp() -> str:
    """Return current local time as an ISO-8601 string with timezone."""
    return datetime.now().astimezone().isoformat()


def build_payload(event_type: str, user_action: str, app_name: str = "", metadata: dict = None) -> dict:
    """Build the JSON body expected by POST /api/agent/log."""
    username = getpass.getuser()
    # Backend resolves hostname from metadata first — always include it for ingestion.
    meta = {"hostname": HOSTNAME, "deviceId": HOSTNAME, "username": username}
    if metadata:
        meta.update(metadata)
    return {
        "timestamp": iso_timestamp(),
        "event_type": event_type,
        "user_action": user_action,
        "application_name": app_name,
        "hostname": HOSTNAME,
        "user_id": USER_ID,
        "username": username,
        "deviceId": HOSTNAME,
        "metadata": meta,
    }


def probe_backend() -> bool:
    """
    GET /api/health once at startup. If the Node server is down, logs still enqueue to SQLite
    but will not appear in the dashboard until the server is reachable.
    """
    try:
        r = requests.get(SERVER_HEALTH_URL, timeout=5)
        ok = r.status_code < 500
        logger.info(f"[BACKEND] probe GET {SERVER_HEALTH_URL} status={r.status_code} ok={ok}")
        if not ok:
            logger.warning(
                "[BACKEND] Server returned an error. Start the SIEM Node server (e.g. npm start in /server) "
                "so queued events can be stored in PostgreSQL."
            )
        return ok
    except requests.RequestException as ex:
        logger.warning(
            f"[BACKEND] probe failed: {ex} — events will stay in offline_logs.sqlite until "
            f"{BACKEND_BASE_URL} is reachable (start: cd server && npm start)."
        )
        return False


def log_event(event_type: str, user_action: str, app_name: str = "", metadata: dict = None):
    """Build payload, apply cooldown dedupe, enqueue for background HTTP send."""
    username = getpass.getuser()
    ok, block_reason = should_emit(
        event_type, user_action, username, HOSTNAME, app_name, metadata
    )
    if not ok:
        emit_duplicate_log(block_reason)
        return

    payload = build_payload(event_type, user_action, app_name, metadata)
    logger.debug(f"Queueing event: {user_action} {app_name}")
    db_queue.enqueue(payload)


def queue_worker():
    """Daemon loop: flush SQLite queue to the backend on POLL_INTERVAL_QUEUE."""
    while True:
        db_queue.flush_queue()
        queue_notify.wait(timeout=POLL_INTERVAL_QUEUE)
        queue_notify.clear()
