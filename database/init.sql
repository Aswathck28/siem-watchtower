-- SIEM Watchtower Database Initialization Script

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    firebase_uid VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'USER',
    current_session_id VARCHAR(255),
    session_start_time TIMESTAMPTZ,
    last_alert_minute INTEGER DEFAULT 0
);

-- 2. System Logs (Windows Events, Agent Logs)
CREATE TABLE IF NOT EXISTS system_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    hostname VARCHAR(255),
    event_type VARCHAR(50),
    mapped_technique_id VARCHAR(50),
    details JSONB
);

-- 3. Network Logs (HTTP Traffic)
CREATE TABLE IF NOT EXISTS network_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    method VARCHAR(10),
    path TEXT,
    status_code INTEGER,
    response_time_ms INTEGER,
    payload_size_bytes INTEGER,
    source_ip VARCHAR(50),
    user_agent TEXT,
    mapped_technique_id VARCHAR(50),
    anomaly_score FLOAT DEFAULT 0.0,
    is_anomaly BOOLEAN DEFAULT FALSE
);

-- 4. Activity Logs (Web Actions, War Games, Login/Logout)
CREATE TABLE IF NOT EXISTS activity_logs (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100),
    action_type VARCHAR(50),
    mapped_technique_id VARCHAR(50),
    details JSONB,
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 5. MITRE ATT&CK Definitions (Populated by seed_mitre.js)
CREATE TABLE IF NOT EXISTS mitre_definitions (
    matrix_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    tactic VARCHAR(255),
    url VARCHAR(255)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_logs_anomaly ON network_logs(is_anomaly) WHERE is_anomaly = TRUE;
CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid);

-- ========================================
-- ARCHIVAL TABLES (mirrors of live tables)
-- ========================================

-- 6. System Logs Archive
CREATE TABLE IF NOT EXISTS system_logs_archive (
    LIKE system_logs INCLUDING DEFAULTS
);
CREATE INDEX IF NOT EXISTS idx_syslog_archive_ts ON system_logs_archive(timestamp DESC);

-- 7. Network Logs Archive
CREATE TABLE IF NOT EXISTS network_logs_archive (
    LIKE network_logs INCLUDING DEFAULTS
);
CREATE INDEX IF NOT EXISTS idx_netlog_archive_ts ON network_logs_archive(timestamp DESC);

-- 8. Activity Logs Archive
CREATE TABLE IF NOT EXISTS activity_logs_archive (
    LIKE activity_logs INCLUDING DEFAULTS
);
CREATE INDEX IF NOT EXISTS idx_actlog_archive_ts ON activity_logs_archive(timestamp DESC);

-- 9. Archive Run History (tracks every archival job)
CREATE TABLE IF NOT EXISTS archive_runs (
    id            SERIAL PRIMARY KEY,
    run_at        TIMESTAMPTZ DEFAULT NOW(),
    cutoff_date   TIMESTAMPTZ,
    rows_system   INTEGER DEFAULT 0,
    rows_network  INTEGER DEFAULT 0,
    rows_activity INTEGER DEFAULT 0,
    total_moved   INTEGER DEFAULT 0,
    status        VARCHAR(20) DEFAULT 'SUCCESS',
    error_msg     TEXT
);

-- ========================================
-- ENTERPRISE DETECTION & RESPONSE TABLES
-- ========================================

-- 10. Detection Rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    severity VARCHAR(50) DEFAULT 'MEDIUM',
    mitre_id VARCHAR(50),
    tactic VARCHAR(255),
    confidence_score INTEGER DEFAULT 50,
    trigger_reason TEXT,
    mitigation TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

-- 11. Triggered Detections
CREATE TABLE IF NOT EXISTS triggered_detections (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255),
    mitre_id VARCHAR(50),
    severity VARCHAR(50),
    confidence_score INTEGER,
    hostname VARCHAR(255),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    trigger_reason TEXT,
    mitigation TEXT,
    evidence JSONB
);

-- 12. Threat Scores
CREATE TABLE IF NOT EXISTS threat_scores (
    entity_id VARCHAR(255) PRIMARY KEY,
    entity_type VARCHAR(50), -- 'USER', 'HOST', 'IP'
    score FLOAT DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'LOW',
    factors JSONB,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 13. Suspicious IPs
CREATE TABLE IF NOT EXISTS suspicious_ips (
    ip_address VARCHAR(50) PRIMARY KEY,
    threat_score FLOAT DEFAULT 0.0,
    reason TEXT,
    last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- Active Alerts is already created in index.js, but let's ensure it's in init.sql for consistency
CREATE TABLE IF NOT EXISTS active_alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    username VARCHAR(100),
    alert_type VARCHAR(255),
    severity VARCHAR(50),
    related_domain TEXT,
    mitre_technique_id VARCHAR(50)
);

-- Enterprise Indexes
CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
CREATE INDEX IF NOT EXISTS idx_trig_det_timestamp ON triggered_detections(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_trig_det_severity ON triggered_detections(severity);
CREATE INDEX IF NOT EXISTS idx_trig_det_mitre ON triggered_detections(mitre_id);
CREATE INDEX IF NOT EXISTS idx_trig_det_hostname ON triggered_detections(hostname);
CREATE INDEX IF NOT EXISTS idx_threat_scores_entity ON threat_scores(entity_id);
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_ip ON suspicious_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_active_alerts_timestamp ON active_alerts(timestamp DESC);
