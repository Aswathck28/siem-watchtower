# SIEM Watchtower — API Documentation

> Base URL: `http://localhost:5000`  
> All request/response bodies are JSON unless stated otherwise.

---

## Authentication

### POST `/api/login`
Logs a user in, creates or updates their session, detects brute-force.

**Request:**
```json
{
  "uid": "firebase-uid-abc123",
  "email": "user@corp.local",
  "status": "success"
}
```
> Set `"status": "fail"` to report a failed login attempt (brute-force tracking).

**Response (success):**
```json
{
  "status": "ok",
  "role": "USER",
  "sessionId": "uuid-v4-session-id"
}
```
**Response (brute-force fail logged):**
```json
{ "status": "denied_logged" }
```

---

### POST `/api/logout`
Ends a user session and logs the event.

**Request:**
```json
{
  "uid": "firebase-uid-abc123",
  "email": "user@corp.local",
  "reason": "User Manual Logout"
}
```
**Response:**
```json
{ "status": "logged_out" }
```

---

## Activity Logging

### POST `/api/log`
Logs any user activity event (clicks, page visits, form submissions, etc.).

**Request:**
```json
{
  "uid": "firebase-uid-abc123",
  "action": "page_visit",
  "details": {
    "url": "https://corp.internal/dashboard",
    "page_title": "Main Dashboard"
  },
  "sessionId": "uuid-v4-session-id"
}
```
**Response:**
```json
{
  "status": "logged",
  "techniqueId": "T1204",
  "anomalyScore": 0.05,
  "isAnomaly": false
}
```

---

### POST `/api/agent/log`
Ingestion endpoint for the PowerShell monitoring agent.

**Request:**
```json
{
  "timestamp": "2026-03-20T10:00:00.000Z",
  "event_type": "FOREGROUND_WINDOW_CHANGE",
  "application_name": "Google Chrome",
  "user_action": "FOREGROUND_WINDOW_CHANGE",
  "severity": "INFO",
  "source": "elite_agent",
  "metadata": {
    "hostname": "DESKTOP-ABC123",
    "window_title": "YouTube - Google Chrome"
  }
}
```
**Response:**
```json
{ "status": "ok" }
```

---

## Dashboard Data

### GET `/api/dashboard-data`
Returns aggregated counts and summaries for the admin dashboard.

**Response:**
```json
{
  "total_users": 12,
  "active_sessions": 3,
  "total_alerts": 45,
  "event_summary": [
    { "event_type": "login_success", "count": 120 },
    { "event_type": "login_fail", "count": 18 },
    { "event_type": "page_visit", "count": 340 }
  ]
}
```

---

### GET `/api/live-stats`
Returns real-time counts for KPI cards.

**Response:**
```json
{
  "total_logs": 1540,
  "active_alerts": 7,
  "anomaly_count": 12,
  "active_sessions": 3
}
```

---

## Logs

### GET `/api/system-logs?limit=50`
Returns Windows/agent system event logs.

| Param | Type | Default | Description |
|---|---|---|---|
| `limit` | number | 50 | Max rows to return |

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-03-20T09:00:00.000Z",
    "hostname": "DESKTOP-ABC123",
    "event_type": "FOREGROUND_WINDOW_CHANGE",
    "mapped_technique_id": "T1204",
    "details": { "window_title": "YouTube - Google Chrome" }
  }
]
```

---

### GET `/api/network-logs?limit=50`
Returns HTTP request logs captured by the network middleware.

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-03-20T09:00:05.000Z",
    "method": "GET",
    "path": "/api/dashboard-data",
    "status_code": 200,
    "response_time_ms": 14,
    "payload_size_bytes": 1024,
    "source_ip": "::1",
    "user_agent": "Mozilla/5.0...",
    "mapped_technique_id": "T1204",
    "anomaly_score": 0.02,
    "is_anomaly": false
  }
]
```

---

### GET `/api/activity-logs?uid=<optional>`
Returns user activity logs (clicks, logins, navigation events).

| Param | Type | Required | Description |
|---|---|---|---|
| `uid` | string | No | Filter logs for a specific user |

---

## Alerts

### GET `/api/alerts`
Returns all active security alerts.

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-03-20T10:05:18.000Z",
    "username": "admin@corp.local",
    "alert_type": "BRUTE_FORCE",
    "severity": "CRITICAL",
    "related_domain": null,
    "mitre_technique_id": "T1110"
  }
]
```

---

## Export

### GET `/api/export`
Downloads logs as CSV or JSON file.

| Param | Type | Options | Description |
|---|---|---|---|
| `table` | string | `system_logs`, `network_logs`, `activity_logs` | Which log table |
| `format` | string | `csv`, `json` | Output format |
| `days` | number | e.g. `7`, `30` | How many days back |
| `include_archive` | string | `true`/`false` | Include archived data |
| `uid` | string | (optional) | Filter by user ID (activity_logs only) |

**Example:** `GET /api/export?table=system_logs&format=csv&days=7`

---

## Archive

### GET `/api/archive/status`
Returns archive stats and last run info.

**Response:**
```json
{
  "retention_days": 30,
  "last_run": { "run_at": "2026-03-01T00:00:00.000Z", "total_moved": 1200, "status": "SUCCESS" },
  "live_counts": {
    "live_system": "450",
    "live_network": "3200",
    "live_activity": "890"
  }
}
```

### POST `/api/archive/run-now`
Manually triggers archival of logs older than 30 days.

**Response:**
```json
{
  "status": "ok",
  "rowsSys": 120,
  "rowsNet": 440,
  "rowsAct": 95,
  "total": 655
}
```

---

## Users (Admin Only)

### GET `/api/users`
Returns all registered users with session info.

**Response:**
```json
[
  {
    "id": 1,
    "firebase_uid": "uid-abc123",
    "email": "user@corp.local",
    "role": "USER",
    "current_session_id": "sess-uuid",
    "session_start_time": "2026-03-20T09:00:00.000Z"
  }
]
```

---

## Health Check

### GET `/api/health`
Quick liveness check.

**Response:**
```json
{ "status": "ok", "timestamp": "2026-03-20T10:00:00.000Z" }
```

---

## MITRE ATT&CK Reference

### GET `/api/mitre`
Returns all MITRE ATT&CK technique definitions from the database.

**Response:**
```json
[
  {
    "technique_id": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access",
    "description": "Adversaries may use brute force techniques to gain access..."
  }
]
```
