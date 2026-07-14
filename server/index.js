require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const seedRules = require('./seed_rules');
const app = express();
const PORT = 5000;

// --- SECURITY HARDENING ---
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');

app.use(helmet()); // Set tactical security headers

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10000, // Increased for live SOC dashboard polling (was 100)
    message: { error: '⚠️ TOO MANY REQUESTS: Tactical cooldown active.' }
});
app.use(limiter);

// --- ML SERVICE CONFIG ---
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';
let mlServiceAvailable = false; // start pessimistic; health check will enable it

// --- HEALTH CHECK: auto-reconnect & auto-disable ML service ---
// Periodic background polling mechanism ensuring the external Python Machine Learning anomaly scoring engine is reachable and dynamically toggles failover states 
/**
 * Function: checkMLHealth
 * Description: Periodic background polling mechanism that verifies the availability 
 *              of the external Python Machine Learning service. Dynamically toggles 
 *              the 'mlServiceAvailable' flag to enable or disable ML-based anomaly 
 *              scoring in the traffic pipeline.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise<void>
 */
const checkMLHealth = async () => {
    try {
        await axios.get(`${ML_SERVICE_URL}/health`, { timeout: 2000 });
        if (!mlServiceAvailable) {
            mlServiceAvailable = true;
            console.log('[ML] ✅ Service is now ONLINE — switching to ML mode.');
        }
    } catch {
        if (mlServiceAvailable) {
            mlServiceAvailable = false;
            console.warn('[ML] ⚠️  Service went OFFLINE — falling back to rule engine.');
        }
    }
};
checkMLHealth(); // immediate check on startup
setInterval(checkMLHealth, 15_000); // re-check every 15 seconds automatically

// Paths the SIEM dashboard polls itself — skip ML scoring to avoid false positives
const INTERNAL_API_PATHS = new Set([
    '/api/dashboard-data', '/api/system-logs', '/api/network-logs',
    '/api/activity-logs', '/api/alerts', '/api/users',
    '/api/mitre', '/api/live-stats', '/api/archive',
    '/api/health', '/api/intel',
]);

// Per-path ML alert cooldown — suppress repeat [ML ALERT] for same path within 60s
const mlAlertCooldown = {};
const ML_ALERT_COOLDOWN_MS = 60_000;

/**
 * callMLService — calls the Python ML microservice for anomaly scoring + MITRE classification.
 * Falls back to rule-based analyzeWebTraffic if the service is unreachable.
 * @param {object} features  - { method, path, status_code, response_time_ms, payload_size_bytes, action_type }
 * @returns {Promise<{techniqueId: string, anomalyScore: number, isAnomaly: boolean, confidence: number}>}
 */
// Transmits live HTTP event parameters to the dedicated Isolation Forest ML service returning an advanced behavioral heuristic score preventing zero-days
/**
 * Function: callMLService
 * Description: Transmits live HTTP event parameters to the dedicated Python ML 
 *              microservice. It retrieves an anomaly score and MITRE technique 
 *              classification based on the behavioral features of the request.
 * Parameters:
 *   - features (object): { method, path, status_code, response_time_ms, payload_size_bytes, action_type }
 * Returns:
 *   - Promise<object|null>: { techniqueId, anomalyScore, isAnomaly, confidence } or null if service is offline.
 */
const callMLService = async (features) => {
    if (!mlServiceAvailable) return null;

    try {
        const { data } = await axios.post(`${ML_SERVICE_URL}/predict`, features, { timeout: 2000 });
        return {
            techniqueId: data.mitre_technique_id,
            anomalyScore: data.anomaly_score,
            isAnomaly: data.is_anomaly,
            confidence: data.confidence,
        };
    } catch (err) {
        mlServiceAvailable = false; // health check will re-enable it in 15s
        return null;
    }
};

// --- CONFIGURATION ---
const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL || 'aswathck28@gmail.com';

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

// Lightweight liveness for agents and load balancers (no DB dependency)
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'siem-watchtower-api', timestamp: new Date().toISOString() });
});

const path = require('path');
// Serve Static Files
app.use(express.static(path.join(__dirname, '../client/build')));

// --- SERVE TARGET CORP PORTAL (Test Site) ---
app.use('/portal', express.static(path.join(__dirname, '../test-site')));

// NETWORK LOGGING MIDDLEWARE - Captures all HTTP requests
// NETWORK LOGGING MIDDLEWARE - Captures all HTTP requests
app.use((req, res, next) => {
    const startTime = Date.now();

    // Hook into response finish event to log after response is sent
    res.on('finish', () => {
        const responseTime = Date.now() - startTime;
        const payloadSize = res.get('Content-Length') || 0;
        const statusCode = res.statusCode;

        // Log network data asynchronously
        setImmediate(async () => {
            try {
                const isInternalPath = INTERNAL_API_PATHS.has(req.path);
                
                // --- USER ISOLATION & COLLECTION START ---
                // Requirement: Website logs must start to collect after login success alone.
                const activeUser = activeUserIpMap[req.ip];
                if (!activeUser && !isInternalPath) {
                    // console.log(`[NETWORK] Dropping log from unauthenticated source ${req.ip} - ${req.path}`);
                    return; // Requirement: Collect after login success alone
                }

                const features = {
                    method: req.method,
                    path: req.path,
                    status_code: statusCode,
                    response_time_ms: responseTime,
                    payload_size_bytes: parseInt(payloadSize) || 0,
                    action_type: 'network_request',
                };

                // --- RULE ENGINE INTEGRATION ---
                const mlResult = isInternalPath ? null : await callMLService(features);
                const ruleResult = SIEMRuleEngine(features.action_type, { path: req.path, method: req.method, statusCode }, mlResult);

                const techniqueId = ruleResult.techniqueId;
                const anomalyScore = ruleResult.riskScore;
                const isAnomaly = ruleResult.isHighSeverity;

                // Rate-limit [ML ALERT] console output — same path can only alert once per 60s
                if (isAnomaly && !isInternalPath) {
                    const alertKey = `${req.method}:${req.path}`;
                    if (!mlAlertCooldown[alertKey]) {
                        console.log(`[RULE ALERT] High Severity detected on ${req.method} ${req.path} — score=${anomalyScore.toFixed(3)} technique=${techniqueId}`);
                        sendSecurityAlert(ruleResult.techniqueId, { ...features, riskScore: anomalyScore });
                        mlAlertCooldown[alertKey] = true;
                        setTimeout(() => delete mlAlertCooldown[alertKey], ML_ALERT_COOLDOWN_MS);

                        // Record enterprise detection
                        recordDetection(pool, {
                            uid: activeUser?.uid || null, hostname: req.ip, techniqueId,
                            anomalyScore, action: 'NETWORK_ANOMALY', details: features
                        });
                    }
                }

                await pool.query(
                    `INSERT INTO network_logs
                       (timestamp, method, path, status_code, response_time_ms, payload_size_bytes, source_ip, user_agent, mapped_technique_id, anomaly_score, is_anomaly, user_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
                    [
                        new Date(),
                        req.method,
                        req.path,
                        statusCode,
                        responseTime,
                        parseInt(payloadSize) || 0,
                        req.ip,
                        req.get('user-agent') || 'Unknown',
                        techniqueId,
                        anomalyScore,
                        isAnomaly,
                        activeUser?.uid || null
                    ]
                );
            } catch (err) {
                console.error('[NETWORK LOG ERROR]', err.message);
            }
        });
    });

    next();
});

// 1. DATABASE CONNECTION
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'siem-watchtower',
    password: process.env.DB_PASS || 'pava4484',
    port: process.env.DB_PORT || 5432,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000, // Increased timeout for stability
});

// Generic Pool Erorr Handler
pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
});

// --- DB INIT ---
// Foundational application startup sequence orchestrating the structural creation and migration of PostgreSQL relationship schemas ensuring data integrity pre-flight
/**
 * Function: initDB
 * Description: Orchestrates the structural creation and migration of the PostgreSQL 
 *              database schema on application startup. Ensures all required tables, 
 *              columns, and indexes for logs, alerts, and user data are initialized 
 *              if they do not already exist.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise<void>
 */
const initDB = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS system_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ,
                hostname VARCHAR(255),
                event_type VARCHAR(50),
                mapped_technique_id VARCHAR(50),
                details JSONB,
                user_id VARCHAR(100)
            );
        `);
        console.log("[DB] System Logs Table Ready");
        await pool.query(`ALTER TABLE system_logs ADD COLUMN IF NOT EXISTS user_id VARCHAR(100);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_system_logs_user ON system_logs(user_id);`).catch(() => { });

        await pool.query(`
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
                user_id VARCHAR(100)
            );
        `);
        console.log("[DB] Network Logs Table Ready");

        // Ensure columns exist if table was already there
        await pool.query(`ALTER TABLE network_logs ADD COLUMN IF NOT EXISTS mapped_technique_id VARCHAR(50);`).catch(() => { });
        await pool.query(`ALTER TABLE network_logs ADD COLUMN IF NOT EXISTS anomaly_score FLOAT DEFAULT 0.0;`).catch(() => { });
        await pool.query(`ALTER TABLE network_logs ADD COLUMN IF NOT EXISTS is_anomaly BOOLEAN DEFAULT FALSE;`).catch(() => { });
        await pool.query(`ALTER TABLE network_logs ADD COLUMN IF NOT EXISTS user_id VARCHAR(100);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_network_logs_anomaly ON network_logs(is_anomaly) WHERE is_anomaly = TRUE;`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_network_logs_user ON network_logs(user_id);`).catch(() => { });

        await pool.query(`
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
        `);
        console.log("[DB] Activity Logs Table Ready");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS active_alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                username VARCHAR(100),
                alert_type VARCHAR(255),
                severity VARCHAR(50),
                related_domain TEXT,
                mitre_technique_id VARCHAR(50)
            );
        `);
        console.log("[DB] Active Alerts Table Ready");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS raw_logs (
                id SERIAL PRIMARY KEY,
                event_type VARCHAR(100),
                timestamp TIMESTAMPTZ,
                user_id VARCHAR(100),
                session_id VARCHAR(100),
                source VARCHAR(50),
                metadata JSONB
            );
        `);
        console.log("[DB] Raw Logs Table Ready");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS correlated_sessions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(100),
                session_id VARCHAR(100),
                start_time TIMESTAMPTZ,
                end_time TIMESTAMPTZ,
                duration_ms INTEGER,
                activity TEXT,
                classification VARCHAR(50),
                confidence_score FLOAT,
                risk_score VARCHAR(20),
                mapped_technique_id VARCHAR(50),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        console.log("[DB] Correlated Sessions Table Ready");

        // Privacy columns
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_tracking BOOLEAN DEFAULT TRUE;`).catch(() => { });
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS anonymize_logs BOOLEAN DEFAULT FALSE;`).catch(() => { });
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS hostname VARCHAR(255);`).catch(() => { });

        console.log("[DB] Using existing 'mitre_definitions' Table");

        // --- ENTERPRISE TABLES ---

        await pool.query(`
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
            -- Migration: Ensure trigger_reason exists if table was created in an older version
            ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS trigger_reason TEXT;
        `);
        console.log("[DB] Detection Rules Table Ready");

        await pool.query(`
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
            -- Migration: Ensure trigger_reason and mitigation exist
            ALTER TABLE triggered_detections ADD COLUMN IF NOT EXISTS trigger_reason TEXT;
            ALTER TABLE triggered_detections ADD COLUMN IF NOT EXISTS mitigation TEXT;
        `);
        console.log("[DB] Triggered Detections Table Ready");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS threat_scores (
                entity_id VARCHAR(255) PRIMARY KEY,
                entity_type VARCHAR(50), 
                score FLOAT DEFAULT 0.0,
                risk_level VARCHAR(20) DEFAULT 'LOW',
                factors JSONB,
                last_updated TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        console.log("[DB] Threat Scores Table Ready");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                ip_address VARCHAR(50) PRIMARY KEY,
                threat_score FLOAT DEFAULT 0.0,
                reason TEXT,
                last_seen TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        console.log("[DB] Suspicious IPs Table Ready");

        await pool.query(`CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_trig_det_timestamp ON triggered_detections(timestamp DESC);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_trig_det_severity ON triggered_detections(severity);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_trig_det_mitre ON triggered_detections(mitre_id);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_trig_det_hostname ON triggered_detections(hostname);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_threat_scores_entity ON threat_scores(entity_id);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_suspicious_ips_ip ON suspicious_ips(ip_address);`).catch(() => { });
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_active_alerts_timestamp ON active_alerts(timestamp DESC);`).catch(() => { });

        // Now seed the rules automatically
        await seedRules(pool);

        // --- NEW: REBUILD ACTIVE HOSTNAMES ON STARTUP ---
        const activeRes = await pool.query("SELECT email, hostname, firebase_uid FROM users WHERE current_session_id IS NOT NULL");
        for (const row of activeRes.rows) {
            const h = await resolveDashboardUserHostname(pool, row.firebase_uid, row.email, row.hostname);
            if (h && !h.startsWith('OFFLINE_NODE_')) {
                activeHostnames.add(h);
                activeHostUserMap[h] = row.firebase_uid;
            }
        }
        console.log(`[INIT] Rebuilt ${activeHostnames.size} active hostnames.`);

    } catch (err) {
        console.error("[DB ERROR]", err);
    }
};
initDB();

/**
 * Resolve PC hostname for filtering system_logs against agent telemetry.
 * Uses users.hostname when set; otherwise matches agent details.username to email local-part
 * (Windows login) and persists the inferred hostname on users.
 */
async function resolveDashboardUserHostname(pool, firebaseUid, email, storedHostname) {
    const raw = storedHostname && String(storedHostname).trim();
    const isPlaceholder = raw && /^OFFLINE_NODE_/i.test(raw);
    if (raw && !isPlaceholder) return raw;

    const localPart = (email || '').split('@')[0] || '';
    if (!localPart) {
        return `OFFLINE_NODE_${String(firebaseUid || '').substring(0, 8)}`;
    }

    try {
        const inferred = await pool.query(
            `
            SELECT hostname FROM system_logs
            WHERE timestamp > NOW() - INTERVAL '30 days'
              AND hostname IS NOT NULL
              AND btrim(hostname) <> ''
              AND details::jsonb->>'username' IS NOT NULL
              AND (
                lower(btrim(details::jsonb->>'username')) = lower(btrim($1::text))
                OR lower(split_part(replace(details::jsonb->>'username', '/', '\\'), '\\', 2))
                   = lower(btrim($1::text))
              )
            ORDER BY timestamp DESC
            LIMIT 1
            `,
            [localPart]
        );

        if (inferred.rows.length && inferred.rows[0].hostname) {
            const h = String(inferred.rows[0].hostname).trim();
            await pool.query(
                `UPDATE users SET hostname = $1 WHERE firebase_uid = $2
                 AND (hostname IS NULL OR btrim(hostname) = '' OR hostname LIKE 'OFFLINE_NODE_%')`,
                [h, firebaseUid]
            ).catch(() => { });
            return h;
        }

        // One machine reporting agent events (common dev setup): use that hostname unambiguously.
        // If multiple hosts exist, we fall back to the most active one as a last resort for demo stability.
        const solo = await pool.query(
            `
            SELECT hostname, COUNT(*)::int AS c
            FROM system_logs
            WHERE timestamp > NOW() - INTERVAL '24 hours'
              AND event_type IN ('AppBehaviour', 'SystemPerformance', 'DeviceControl', 'Authentication', 'SYSTEM_INFO_EVENT_1')
              AND hostname IS NOT NULL
              AND btrim(hostname) <> ''
            GROUP BY hostname
            ORDER BY c DESC
            LIMIT 1
            `,
        );
        if (solo.rows.length && solo.rows[0].hostname) {
            const h = String(solo.rows[0].hostname).trim();
            await pool.query(
                `UPDATE users SET hostname = $1 WHERE firebase_uid = $2
                 AND (hostname IS NULL OR btrim(hostname) = '' OR hostname LIKE 'OFFLINE_NODE_%')`,
                [h, firebaseUid]
            ).catch(() => { });
            return h;
        }
    } catch (e) {
        console.warn('[resolveDashboardUserHostname]', e.message);
    }

    return `OFFLINE_NODE_${String(firebaseUid || '').substring(0, 8)}`;
}

// --- SESSION & APPLICATION DURATION MONITOR ---
// Periodically checks active sessions and alerts on extended durations (>1 hour) per SOC security guidelines
setInterval(async () => {
    try {
        const activeUsers = await pool.query(
            "SELECT firebase_uid, email, hostname, session_start_time FROM users WHERE current_session_id IS NOT NULL"
        );
        for (const row of activeUsers.rows) {
            const start = new Date(row.session_start_time);
            const now = new Date();
            const durationHrs = (now - start) / (1000 * 60 * 60);

            // Requirement: Collect log of application (session) running more than 1 hour
            if (durationHrs > 1) {
                const resolvedHost = await resolveDashboardUserHostname(pool, row.firebase_uid, row.email, row.hostname);
                
                // Insert a 'LONG_RUNNING_APP' alert for the user to see in their feed
                const detailsObj = { 
                    message: `Forensic Alert: Workstation Session / Elite Agent has been running for ${durationHrs.toFixed(1)} hours.`,
                    duration_hours: durationHrs.toFixed(1),
                    application: 'SIEM Watchtower Agent'
                };
                await pool.query(
                    `INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details, user_id) 
                     SELECT NOW(), $1::text, 'LONG_RUNNING_APP', 'T1078', $2::jsonb, $3::text
                     WHERE NOT EXISTS (
                        SELECT 1 FROM system_logs 
                        WHERE hostname = $1 AND event_type = 'LONG_RUNNING_APP' 
                        AND timestamp > NOW() - INTERVAL '30 minutes'
                     )`,
                    [
                        resolvedHost,
                        JSON.stringify(detailsObj),
                        row.firebase_uid
                    ]
                );
            }
        }
    } catch (e) {
        console.warn('[DURATION_MONITOR] Error:', e.message);
    }
}, 5 * 60 * 1000); // Check every 5 minutes
const failedSystemAttempts = {};
const failedAttempts = {};
const ipAccountMap = {};
const activeUserIpMap = {}; // { ip: { uid, email, role } }
const activeHostnames = new Set(); // Set of hostnames with active sessions
const activeHostUserMap = {}; // { hostname: firebase_uid } for per-user system log isolation
const batteryTracking = {}; // { hostname: { level: 100, status: 2, timestamp: Date } }
const perfTracking = {};    // { hostname: { cpu: 15, ram: 4096, timestamp: Date } }
const agentLogDebounce = {}; // In-memory debounce map for noisy agent logs (Transient events)
const activityLogDebounce = {}; // In-memory debounce for frontend /api/log events
const agentState = {};       // In-memory state tracking for apps (hostname -> app -> state)
const agentCommandQueue = {}; // Remote commands for agents: { hostname: [commands] }
const inMemoryAgentLogs = []; // Fallback store if DB insert/query fails (demo stability)
const activeTabSessions = {}; // IN-MEMORY TAB TRACKING: { userId: { sessionId, awayStartTime } }
let autoDefendMode = false;   // Global toggle for automatic counter-measures

// --- LOG RATE LIMITING ---
const logStats = {
    nxlogHits: 0,
    firewallBlocks: 0,
    otherEvents: 0,
    perfHits: 0,
    lastResetTime: Date.now()
};

// Print summary every 10 seconds instead of flooding console
setInterval(() => {
    if (logStats.nxlogHits > 0 || logStats.firewallBlocks > 0 || logStats.otherEvents > 0) {
        // console.log(`[NXLOG SUMMARY] Last 10s: ${logStats.nxlogHits} requests | ${logStats.firewallBlocks} firewall blocks | ${logStats.otherEvents} other events`);
        logStats.nxlogHits = 0;
        logStats.firewallBlocks = 0;
        logStats.otherEvents = 0;
        logStats.lastResetTime = Date.now();
    }
}, 10000);

// =============================================================
// --- ARCHIVAL SYSTEM ---
// Moves logs older than RETENTION_DAYS from live → archive tables
// =============================================================
const RETENTION_DAYS = 30;
let lastArchiveRun = null;

// Automated database maintenance cron mechanism seamlessly migrating aged transactional records into cold storage tables preserving immediate query performance
/**
 * Function: runArchival
 * Description: Maintenance routine that migrates logs older than a specified 
 *              retention period (default 30 days) from live tables to dedicated 
 *              archive tables. This prevents the primary database tables from 
 *              becoming bloated and maintains query performance.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise<object>: Statistical summary of the archival run (rows moved, cutoff date).
 */
const runArchival = async () => {
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
    let rowsSys = 0, rowsNet = 0, rowsAct = 0;
    try {
        // System logs
        const r1 = await pool.query(
            `INSERT INTO system_logs_archive SELECT * FROM system_logs WHERE timestamp < $1
             ON CONFLICT DO NOTHING`, [cutoff]);
        await pool.query(`DELETE FROM system_logs WHERE timestamp < $1`, [cutoff]);
        rowsSys = r1.rowCount || 0;

        // Network logs
        const r2 = await pool.query(
            `INSERT INTO network_logs_archive SELECT * FROM network_logs WHERE timestamp < $1
             ON CONFLICT DO NOTHING`, [cutoff]);
        await pool.query(`DELETE FROM network_logs WHERE timestamp < $1`, [cutoff]);
        rowsNet = r2.rowCount || 0;

        // Activity logs
        const r3 = await pool.query(
            `INSERT INTO activity_logs_archive SELECT * FROM activity_logs WHERE timestamp < $1
             ON CONFLICT DO NOTHING`, [cutoff]);
        await pool.query(`DELETE FROM activity_logs WHERE timestamp < $1`, [cutoff]);
        rowsAct = r3.rowCount || 0;

        const total = rowsSys + rowsNet + rowsAct;

        // Record the run
        await pool.query(
            `INSERT INTO archive_runs (cutoff_date, rows_system, rows_network, rows_activity, total_moved, status)
             VALUES ($1, $2, $3, $4, $5, 'SUCCESS')`,
            [cutoff, rowsSys, rowsNet, rowsAct, total]
        );

        lastArchiveRun = new Date();
        console.log(`[ARCHIVE] ✅ Archival complete. Moved ${total} rows (sys:${rowsSys} net:${rowsNet} act:${rowsAct}) older than ${cutoff.toDateString()}`);
        return { rowsSys, rowsNet, rowsAct, total, cutoff };
    } catch (err) {
        await pool.query(
            `INSERT INTO archive_runs (cutoff_date, rows_system, rows_network, rows_activity, total_moved, status, error_msg)
             VALUES ($1, $2, $3, $4, $5, 'FAILED', $6)`,
            [cutoff, rowsSys, rowsNet, rowsAct, rowsSys + rowsNet + rowsAct, err.message]
        ).catch(() => { });
        console.error('[ARCHIVE] ❌ Archival failed:', err.message);
        throw err;
    }
};

// Run archival every 48 hours automatically
const ARCHIVE_INTERVAL_MS = 48 * 60 * 60 * 1000;
setInterval(async () => {
    try { await runArchival(); } catch (e) { /* already logged */ }
}, ARCHIVE_INTERVAL_MS);
console.log(`[INFO] Archival Scheduler active (Every 48h). Logs older than ${RETENTION_DAYS} days will be archived.`);

// --- MANUAL ARCHIVE TRIGGER ---
// Immediate override endpoint granting SOC administrators explicit capacity to synchronously fire the historical data archival maintenance sub-routine
app.post('/api/archive/run-now', async (req, res) => {
    try {
        const result = await runArchival();
        res.json({ status: 'ok', ...result });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- ARCHIVE STATUS ---
// Diagnostic endpoint rendering structural database row counts indicating database weight constraints and subsequent archival execution timelines
app.get('/api/archive/status', async (req, res) => {
    try {
        const [lastRun, counts] = await Promise.all([
            pool.query(`SELECT * FROM archive_runs ORDER BY run_at DESC LIMIT 5`),
            pool.query(`
                SELECT
                    (SELECT COUNT(*) FROM system_logs)          AS live_system,
                    (SELECT COUNT(*) FROM network_logs)         AS live_network,
                    (SELECT COUNT(*) FROM activity_logs)        AS live_activity,
                    (SELECT COUNT(*) FROM system_logs_archive)  AS arch_system,
                    (SELECT COUNT(*) FROM network_logs_archive) AS arch_network,
                    (SELECT COUNT(*) FROM activity_logs_archive) AS arch_activity
            `)
        ]);

        const nextRun = lastArchiveRun
            ? new Date(lastArchiveRun.getTime() + ARCHIVE_INTERVAL_MS)
            : null;

        res.json({
            retention_days: RETENTION_DAYS,
            last_run: lastRun.rows[0] || null,
            run_history: lastRun.rows,
            next_run: nextRun,
            live_counts: counts.rows[0],
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- EXPORT LOGS (CSV / JSON) ---
// Secure egress capability translating raw backend database logs dynamically into requested downloadable schemas corresponding to queried target views
app.get('/api/export', async (req, res) => {
    const { table = 'system_logs', format = 'csv', days = 30, include_archive = 'false', uid, requester_uid } = req.query;

    const ALLOWED_TABLES = ['system_logs', 'network_logs', 'activity_logs'];
    if (!ALLOWED_TABLES.includes(table)) {
        return res.status(400).json({ error: 'Invalid table. Choose: system_logs, network_logs, activity_logs' });
    }

    // --- REQUIRE AUTH FOR EXPORT ---
    // If not exporting personal logs (uid), must be an admin.
    if (!uid) {
        if (!requester_uid) return res.status(400).json({ error: 'requester_uid or uid required for export' });
        const adminRes = await pool.query('SELECT role FROM users WHERE firebase_uid = $1 LIMIT 1', [requester_uid]);
        if (!adminRes.rows.length || adminRes.rows[0].role !== 'ADMIN') {
            return res.status(403).json({ error: 'Admin access required for global export' });
        }
    }

    try {
        const boundedDays = parseBoundedInt(days, 30, 1, 365);
        const cutoff = new Date(Date.now() - boundedDays * 24 * 60 * 60 * 1000);
        const params = [cutoff];
        let filterClause = "";

        // --- ENFORCE DATA ISOLATION ---
        // If UID is provided (or if user is not admin - though here we rely on the requester providing their UID)
        // We ensure they can only export their own logs.
        if (uid) {
            if (table === 'activity_logs') {
                filterClause = " AND user_id = $2";
                params.push(uid);
            } else if (table === 'system_logs') {
                // For system logs, we need to resolve the hostname for this UID
                const ur = await pool.query('SELECT hostname, email FROM users WHERE firebase_uid = $1', [uid]);
                if (ur.rows.length > 0) {
                    const h = await resolveDashboardUserHostname(pool, uid, ur.rows[0].email, ur.rows[0].hostname);
                    filterClause = " AND hostname = $2";
                    params.push(h);
                } else {
                    return res.status(403).json({ error: 'User not found or access denied' });
                }
            } else if (table === 'network_logs') {
                filterClause = " AND user_id = $2";
                params.push(uid);
            }
        } else {
            // Requirement: No user can see other users logs. 
            // If no UID is provided, and it's not an internal admin call (which we don't have a check for here yet),
            // we should probably deny access if we want strict isolation.
            // For now, let's assume if no UID is provided, it's a global export (Admin).
        }

        // Optionally include archive data
        let query;
        if (include_archive === 'true') {
            query = `SELECT * FROM ${table} WHERE timestamp >= $1${filterClause}
                     UNION ALL
                     SELECT * FROM ${table}_archive WHERE timestamp >= $1${filterClause}
                     ORDER BY timestamp DESC`;
        } else {
            query = `SELECT * FROM ${table} WHERE timestamp >= $1${filterClause} ORDER BY timestamp DESC`;
        }

        const result = await pool.query(query, params);
        const rows = result.rows;
        const filename = `${table}_last${boundedDays}days_${new Date().toISOString().slice(0, 10)}`;

        if (format === 'json') {
            res.setHeader('Content-Disposition', `attachment; filename="${filename}.json"`);
            res.setHeader('Content-Type', 'application/json');
            return res.json(rows);
        }

        // CSV format
        res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
        res.setHeader('Content-Type', 'text/csv');

        if (rows.length === 0) return res.send('No data found for the selected range.');

        const headers = Object.keys(rows[0]);
        const csvLines = [
            headers.join(','),
            ...rows.map(row =>
                headers.map(h => {
                    const val = row[h];
                    if (val === null || val === undefined) return '';
                    const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
                    // Escape commas and quotes
                    return str.includes(',') || str.includes('"') || str.includes('\n')
                        ? `"${str.replace(/"/g, '""')}"`
                        : str;
                }).join(',')
            )
        ];
        return res.send(csvLines.join('\n'));

    } catch (e) {
        console.error('[EXPORT ERROR]', e.message);
        res.status(500).json({ error: 'Export failed: ' + e.message });
    }
});

// --- EMAIL SETUP (ALERTS) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'aswathck28@gmail.com',
        pass: process.env.EMAIL_PASS // Ensure this is set in .env
    }
});

// --- HELPER: GET DESTINATION IP ---
const getDestIp = (req) => req.socket.localAddress || '127.0.0.1';
const ADMIN_COMMAND_ALLOWLIST = new Set(['LOCK', 'UNLOCK', 'ISOLATE_NETWORK', 'ENABLE_NETWORK', 'KILL_PROCESS']);
const validBoolean = (value) => typeof value === 'boolean';
const parseBoundedInt = (value, fallback, min, max) => {
    const parsed = Number.parseInt(value, 10);
    if (Number.isNaN(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
};

const requireAdminRequester = async (req, res, next) => {
    const requesterUid = (req.body && req.body.requester_uid) || (req.query && req.query.requester_uid);
    if (!requesterUid || typeof requesterUid !== 'string') {
        return res.status(400).json({ error: 'requester_uid is required' });
    }
    try {
        const adminRes = await pool.query('SELECT role FROM users WHERE firebase_uid = $1 LIMIT 1', [requesterUid]);
        if (!adminRes.rows.length || adminRes.rows[0].role !== 'ADMIN') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.requester_uid = requesterUid;
        return next();
    } catch (e) {
        return res.status(500).json({ error: 'Authorization check failed' });
    }
};

// --- NEW: NOTIFY ALL ADMINS FUNCTION ---
// Mail routing orchestrator compiling all administrative personnel and broadcasting structured situational awareness payload regarding critical anomalies
/**
 * Function: notifyAllAdmins
 * Description: Retrieves all administrator emails from the database (plus the 
 *              super-admin) and broadcasts a security alert via Nodemailer.
 * Parameters:
 *   - subject (str): The email subject line.
 *   - text (str): The body content of the email alert.
 * Returns:
 *   - Promise<void>
 */
const notifyAllAdmins = async (subject, text) => {
    try {
        const result = await pool.query("SELECT email FROM users WHERE role = 'ADMIN'");
        const adminEmails = result.rows.map(r => r.email);
        const recipients = [...new Set([...adminEmails, SUPER_ADMIN_EMAIL])];
        if (recipients.length === 0) return;

        const mailOptions = {
            from: 'SIEM Watchtower <noreply@siem.local>',
            to: recipients,
            subject: subject,
            text: text
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.log('[MAIL FAIL]', error);
            else console.log(`[BROADCAST SENT] To: ${recipients.length} Admins`);
        });
    } catch (e) { console.error("Failed to fetch admins", e); }
};

// Unified Alert Function
// Constructs and wraps dynamically generated breach templates invoking the notification broadcaster when extreme risk signatures are confirmed
/**
 * Function: sendSecurityAlert
 * Description: High-level wrapper for security notifications. Maps a security 
 *              event type to a human-readable subject and constructs a detailed 
 *              alert payload before invoking notifyAllAdmins.
 * Parameters:
 *   - type (str): The event key (e.g., 'BRUTE_FORCE', 'SQL_INJECTION').
 *   - details (object): Metadata and context related to the specific incident.
 * Returns:
 *   - void
 */
const sendSecurityAlert = (type, details) => {
    const subjects = {
        'NEW_USER': '🚨 SIEM ALERT: New Agent Detected',
        'LONG_SESSION': '⚠️ SIEM WARNING: Extended User Session (>5 Mins)',
        'USER_DELETED': '❌ SIEM ALERT: Agent Account Terminated',
        'BRUTE_FORCE': '🔥 CRITICAL: Brute Force Pattern Detected',
        'LOGOUT_EVENT': 'ℹ️ SIEM: Session Terminated',
        'MULTI_ACCOUNT_IP': '⚠️ SECURITY ALERT: Multiple Accounts from Single IP',
        'BATTERY_DRAIN': '🔋 BATTERY CRITICAL: Rapid Drain Detected',
        'SQL_INJECTION': '💉 CRITICAL: SQL Injection Attempt',
        'XSS_ATTACK': '🦠 CRITICAL: Cross-Site Scripting (XSS) Detected'
    };

    const subject = subjects[type] || `🚨 SIEM ALERT: ${type}`;
    const text = `SECURITY EVENT DETECTED:\n\nTYPE: ${type}\nRISK_SCORE: ${details.riskScore || 'N/A'}\nTECHNIQUE: ${details.techniqueId || 'N/A'}\nDETAILS:\n${JSON.stringify(details, null, 2)}\n\nTimestamp: ${new Date().toISOString()}`;

    // Broadast to all admins
    notifyAllAdmins(subject, text);
};

/**
 * SIEMRuleEngine - The brain of the Watchtower.
 * Combines ML Anomaly Scores with Heuristic Rules to generate Final Alerts.
 */
// Fallback local identification node matching structural incoming traffic payloads against statically defined MITRE ATT&CK adversarial expression dictionaries
/**
 * Function: SIEMRuleEngine
 * Description: The analytical "brain" of the Watchtower. Evaluates incoming 
 *              traffic payloads against a dictionary of known malicious 
 *              patterns (Heuristics) and correlates them with ML scores to 
 *              assign a MITRE technique ID and risk level.
 * Parameters:
 *   - action (str): The event category.
 *   - details (object): The raw data/payload being analyzed.
 *   - mlResult (object|null): Optional anomaly data from the Python service.
 * Returns:
 *   - object: { techniqueId, riskScore, isHighSeverity, alertType }
 */
const SIEMRuleEngine = (action, details, mlResult = null) => {
    const type = (action || '').toLowerCase();
    const payload = JSON.stringify(details).toLowerCase();
    let techniqueId = 'T1204'; // Default: User Execution
    let riskScore = mlResult?.anomalyScore || 0;
    let isHighSeverity = false;

    // --- HEURISTIC RULE CHECKS ---
    const patterns = {
        'T1190': ['union select', 'drop table', '1=1', 'waitfor delay', 'shutdown', 'sql_injection'],
        'T1059.007': ['<script>', 'onerror=', 'javascript:', 'xss_attack', 'onload='],
        'T1083': ['../', '..\\', '/etc/passwd', 'boot.ini', 'path_traversal'],
        'T1110': ['login_fail', 'brute_force'],
        'T1098': ['promote_admin', 'delete_user', 'change_password'],
        'T1136.001': ['create_user'],
        'T1078': ['unauthorized_face_detected', 'unauthorized_access'],  // Valid Accounts - Facial Mismatch
        'T1499': ['application_error', 'app_crash'] // Endpoint Denial of Service
    };

    for (const [tid, keywords] of Object.entries(patterns)) {
        if (keywords.some(k => payload.includes(k) || type.includes(k))) {
            techniqueId = tid;
            riskScore += 0.5; // Bump risk for pattern match
            isHighSeverity = true;
            break;
        }
    }

    // --- ML CORRELATION ---
    if (mlResult?.isAnomaly) {
        riskScore += 0.3;
        if (mlResult.confidence > 0.8) isHighSeverity = true;
    }

    return {
        techniqueId,
        riskScore: Math.min(1.0, riskScore),
        isHighSeverity,
        alertType: isHighSeverity ? '[CRITICAL_THREAT]' : '[INFO_LOG]'
    };
};
const analyzeWebTraffic = (a, d) => SIEMRuleEngine(a, d).techniqueId; // Backward compatibility

// --- ENTERPRISE EVENT RECORDER ---
// Normalization engine parsing disparate logging types specifically evaluating them against administrative detection configuration before database storage
/**
 * Function: recordDetection
 * Description: Normalizes disparate logging data and formally records a 
 *              high-severity security detection in the database. Updates 
 *              the entity's threat score and severity levels for the SOC view.
 * Parameters:
 *   - pool (obj): PostgreSQL connection pool.
 *   - { uid, hostname, techniqueId, anomalyScore, action, details } (object): detection context.
 * Returns:
 *   - Promise<object>: The matched detection rule summary.
 */
const recordDetection = async (pool, { uid, hostname, techniqueId, anomalyScore, action, details }) => {
    try {
        const clientIp = hostname || 'Unknown IP';
        const alertType = (action || 'ANOMALY').toUpperCase();

        // Use default rule values to avoid deadlock during startup seeding
        let rule = { rule_name: alertType, severity: 'CRITICAL', trigger_reason: action, confidence_score: 80, mitigation: 'Review logs and isolate host.' };
        try {
            const ruleRes = await pool.query('SELECT * FROM detection_rules WHERE mitre_id = $1 LIMIT 1', [techniqueId]);
            if (ruleRes.rows[0]) {
                rule = ruleRes.rows[0];
            }
        } catch (ruleErr) {
            // Silently use default rule if detection_rules table is locked/being seeded
            if (ruleErr.code === '40P01') {
                console.log('[RECORD DETECTION] Deadlock avoided - using default rule values during seeding');
            }
        }

        await pool.query(
            `INSERT INTO triggered_detections (rule_name, mitre_id, severity, confidence_score, hostname, trigger_reason, mitigation, evidence)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [rule.rule_name, techniqueId, rule.severity, rule.confidence_score, clientIp, rule.trigger_reason, rule.mitigation, JSON.stringify({
                IP: clientIp, username: uid, hostname: clientIp, device: 'Unknown', raw_snippet: details, timestamp: new Date().toISOString(), anomaly_score: anomalyScore
            })]
        );

        const scoreIncr = rule.severity === 'CRITICAL' ? 25 : (rule.severity === 'HIGH' ? 15 : (rule.severity === 'MEDIUM' ? 8 : 3));
        const entityId = uid || clientIp;
        await pool.query(`
            INSERT INTO threat_scores (entity_id, entity_type, score, risk_level, factors, last_updated)
            VALUES ($1, $2, $3, 'LOW', $4, NOW())
            ON CONFLICT (entity_id) DO UPDATE SET
                score = LEAST(100, threat_scores.score + $3),
                risk_level = CASE
                    WHEN LEAST(100, threat_scores.score + $3) >= 75 THEN 'CRITICAL'
                    WHEN LEAST(100, threat_scores.score + $3) >= 50 THEN 'HIGH'
                    WHEN LEAST(100, threat_scores.score + $3) >= 25 THEN 'MEDIUM'
                    ELSE 'LOW' END,
                factors = (threat_scores.factors || $4::jsonb),
                last_updated = NOW()
        `, [entityId, uid ? 'USER' : 'IP', scoreIncr, JSON.stringify([{ reason: rule.rule_name, severity: rule.severity, ts: new Date().toISOString() }])]);

        await pool.query(
            `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
             VALUES ($1, $2, $3, $4)`,
            [uid || 'SYSTEM_AGENT', alertType, rule.severity, techniqueId]
        );

        return rule;
    } catch (e) {
        console.error('[RECORD DETECTION ERROR]', e);
    }
};

// --- ROUTES ---

// --- EXPLICIT SECURITY INTERCEPTOR MIDDLEWARE ---
app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
        const payloadStr = JSON.stringify(req.body || {}).toLowerCase();
        const pathLower = req.path.toLowerCase();
        const queryStr = JSON.stringify(req.query || {}).toLowerCase();

        const fullCheck = payloadStr + " " + pathLower + " " + queryStr;
        let intercepted = false;
        let action = '';
        let techniqueId = '';

        if (fullCheck.includes('union select') || fullCheck.includes('drop table') || fullCheck.includes('1=1') || fullCheck.includes('waitfor delay') || fullCheck.includes('shutdown')) {
            intercepted = true; action = 'sql_injection'; techniqueId = 'T1190';
        } else if (fullCheck.includes('<script>') || fullCheck.includes('onerror=') || fullCheck.includes('javascript:')) {
            intercepted = true; action = 'xss_attack'; techniqueId = 'T1059.007';
        } else if (fullCheck.includes('../') || fullCheck.includes('..\\\\') || fullCheck.includes('/etc/passwd') || fullCheck.includes('boot.ini')) {
            intercepted = true; action = 'path_traversal'; techniqueId = 'T1083';
        }

        if (intercepted) {
            console.log(`[SECURITY INTERCEPT] ${action} detected from ${req.ip}`);
            const uid = req.body.uid || req.body.requester_uid || 'UNKNOWN_OR_UNAUTH';
            pool.query(
                'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
                [uid, action, techniqueId, JSON.stringify({ path: req.path, payload: req.body }), req.ip, getDestIp(req)]
            ).catch(e => console.error('[INTERCEPT LOG ERROR]', e));

            recordDetection(pool, { uid, hostname: req.ip, techniqueId, anomalyScore: 0.9, action, details: { path: req.path, payload: req.body } });

            // --- AUTO DEFEND: ATTACKER LOCKDOWN ---
            if (autoDefendMode) {
                // Find any online host matching this IP or just the primary host for demo
                // For the demo, we'll queue a LOCK for all connected agents to show 'Swarms' defending
                Object.keys(agentCommandQueue).forEach(hostname => {
                    agentCommandQueue[hostname].push({ id: uuidv4(), command: 'LOCK', params: { reason: `Auto-Defend: ${action} detected` }, timestamp: new Date() });
                });
            }
        }
    }
    next();
});

// 1. LOGIN & ROLE ASSIGNMENT
/**
 * Route: POST /api/login
 * Description: Validates user credentials, assigns administrative roles, 
 *              initiates a secure backend session, and checks for 
 *              brute-force or multi-account IP anomalies.
 * Parameters:
 *   - email (str): User identifier.
 *   - uid (str): Firebase UID.
 *   - status (str|null): Optional status from frontend auth hook.
 * Returns:
 *   - JSON: { status, role, sessionId }
 */
app.post('/api/login', [
    body('email').isEmail().withMessage('Enter a valid email'),
    body('password').optional().isLength({ min: 1 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { uid, email, status, reason, auth_mode } = req.body;
    const clientIp = req.ip;
    const destIp = getDestIp(req);
    const sessionId = uuidv4();
    const role = email === SUPER_ADMIN_EMAIL ? 'ADMIN' : 'USER';

    // --- BRUTE FORCE & SIGNUP CHECK ---
    if (status === 'fail') {
        const failReason = reason || 'auth/unknown';
        const failMode = auth_mode || 'LOGIN';
        
        // Log the specific failure reason to activity_logs
        let userAction = 'login_fail';
        let mappedTechnique = 'T1110'; // Brute Force by default

        if (failReason === 'auth/email-already-in-use') {
            userAction = 'signup_fail_existing_email';
            mappedTechnique = 'T1078'; // Valid Accounts (someone trying to re-register or probe emails)
        } else if (failReason === 'auth/wrong-password' || failReason === 'auth/invalid-credential') {
            userAction = 'login_fail_bad_pass';
            mappedTechnique = 'T1110';
        }

        const failDetails = { 
            user: email, 
            reason: failReason, 
            mode: failMode,
            source_ip: clientIp 
        };

        try {
            await pool.query(
                'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
                [uid || 'unknown', userAction, mappedTechnique, JSON.stringify(failDetails), clientIp, destIp]
            );
        } catch (e) { }

        // Only count brute force for bad passwords, not for existing emails in signup
        if (failReason !== 'auth/email-already-in-use') {
            failedAttempts[clientIp] = failedAttempts[clientIp] || { count: 0, usernames: [] };
            failedAttempts[clientIp].count++;
            if (email) failedAttempts[clientIp].usernames.push(email);

            // Trigger brute force alert after 3 failed attempts
            if (failedAttempts[clientIp].count >= 3) {
                const alertDetails = {
                    source_ip: clientIp,
                    destination_ip: destIp,
                    attempts: failedAttempts[clientIp].count,
                    usernames: [...new Set(failedAttempts[clientIp].usernames)],
                    message: `BRUTE FORCE ATTACK DETECTED: ${failedAttempts[clientIp].count} failed login attempts from IP ${clientIp}. Most recent reason: ${failReason}`,
                    riskScore: 0.95,
                    techniqueId: 'T1110'
                };
                
                sendSecurityAlert('BRUTE_FORCE', alertDetails);

                recordDetection(pool, {
                    uid: email || 'unknown',
                    hostname: clientIp,
                    techniqueId: 'T1110',
                    anomalyScore: 0.95,
                    action: 'BRUTE_FORCE',
                    details: alertDetails
                });

                // Reset counter after alerting
                failedAttempts[clientIp].count = 0;
                failedAttempts[clientIp].usernames = [];
            }
        }
        
        return res.status(200).json({ status: 'denied_logged', reason: failReason });
    }

    // --- SUCCESSFUL LOGIN ---
    try {
        delete failedAttempts[clientIp];

        if (!ipAccountMap[clientIp]) ipAccountMap[clientIp] = new Set();

        if (ipAccountMap[clientIp].size > 0 && !ipAccountMap[clientIp].has(email)) {
            const existingUsers = Array.from(ipAccountMap[clientIp]);
            sendSecurityAlert('MULTI_ACCOUNT_IP', {
                source_ip: clientIp, current_user: email, previous_users: existingUsers,
                message: "Multiple different accounts accessed from the same IP address."
            });
        }
        ipAccountMap[clientIp].add(email);

        const check = await pool.query('SELECT firebase_uid, role FROM users WHERE firebase_uid = $1', [uid]);
        const finalRole = (check.rows[0]?.role || role);

        // --- NEW: UPDATE ACTIVE USER IP MAP ---
        activeUserIpMap[clientIp] = { uid, email, role: finalRole };

        // --- NEW: UPDATE ACTIVE HOSTNAMES ---
        const h = await resolveDashboardUserHostname(pool, uid, email, check.rows[0]?.hostname);
        if (h && !h.startsWith('OFFLINE_NODE_')) {
            activeHostnames.add(h);
            activeHostUserMap[h] = uid;
        }

        if (check.rowCount === 0) {
            console.log(`[NEW USER] ${email} detected.`);
            sendSecurityAlert('NEW_USER', { user: email, uid: uid, status: 'Access Granted', source_ip: clientIp });

            await pool.query(
                `INSERT INTO users (firebase_uid, email, role, current_session_id, session_start_time, last_alert_minute) 
           VALUES ($1, $2, $3, $4, NOW(), 0)`,
                [uid, email, role, sessionId]
            );

            await pool.query(
                'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
                [uid, 'create_user', 'T1136.001', JSON.stringify({ email, role }), clientIp, destIp]
            );
        } else {
            // Update session AND last_login explicitly if needed, but session_start_time covers it
            await pool.query(
                `UPDATE users SET current_session_id = $1, session_start_time = NOW(), last_alert_minute = 0 
             WHERE firebase_uid = $2`,
                [sessionId, uid]
            );
        }

        // --- NEW: IMMEDIATE LOG COLLECTION UPON LOGIN (FOR ALL USERS) ---
        // Requirement: Website logs must show "Logged in" and System logs must show "Battery %" immediately.
        const loginHostname = h || 'UNKNOWN_HOST';
        
        // Get actual battery info from tracking - don't show fake data
        const batteryInfo = batteryTracking[loginHostname];
        
        // Only show battery status if we have real data from the agent
        if (batteryInfo && batteryInfo.level !== null && batteryInfo.level !== undefined) {
            // Normalize status display
            const displayStatus = (typeof batteryInfo.status === 'number') 
                ? (batteryInfo.status === 1 ? 'DISCHARGING' : 'AC_POWER')
                : (batteryInfo.status || 'AC_POWER');

            // 1. System Log: Initial Battery Status (deduped)
            const batteryPayload = JSON.stringify({
                level: batteryInfo.level,
                status_text: displayStatus,
                message: `Initial System Health Check: Battery Level is ${batteryInfo.level}% (${displayStatus})`
            });
        const recentBattery = await pool.query(
            `SELECT id
             FROM system_logs
             WHERE hostname = $1
               AND user_id = $2
               AND event_type = 'BATTERY_STATUS'
               AND details::text = $3
               AND timestamp > NOW() - INTERVAL '10 minutes'
             LIMIT 1`,
            [loginHostname, uid, batteryPayload]
        );
        if (recentBattery.rows.length === 0) {
            await pool.query(
                `INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details, user_id) VALUES
                (NOW(), $1, 'BATTERY_STATUS', 'T1204', $2, $3)`,
                [loginHostname, batteryPayload, uid]
            );
        }
        } // End of battery info check

        // 2. Website Logs: Login related activity (Timeline Isolation)
        await pool.query(
            `INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip, timestamp) VALUES 
            ($1, 'session_initiated', 'T1078', $2, $3, $4, NOW() - INTERVAL '3 seconds'),
            ($1, 'login_success', 'T1078', $5, $3, $4, NOW() - INTERVAL '2 seconds'),
            ($1, 'dashboard_access', 'T1204', $6, $3, $4, NOW() - INTERVAL '1 second')`,
            [
                uid,
                JSON.stringify({ email, event: 'Session handshake complete' }),
                clientIp,
                destIp,
                JSON.stringify({ email, status: 'Logged in', provider: 'Firebase Auth', message: 'User logged in successfully' }),
                JSON.stringify({ page: '/dashboard', message: 'User entered security command center' })
            ]
        );

        res.json({ status: 'ok', role: (check.rows[0]?.role || role), sessionId });
    } catch (err) { res.status(500).send('Error'); }
});

// 2. LOGOUT
/**
 * Route: POST /api/logout
 * Description: Terminates a secure session. Calculates and logs the total 
 *              session duration for activity auditing and clears the session 
 *              identifier from the database.
 * Parameters:
 *   - uid (str): User identifier.
 *   - email (str): User email.
 *   - reason (str|null): Reason for termination.
 * Returns:
 *   - JSON: { status: 'logged_out' }
 */
app.post('/api/logout', [
    body('uid').notEmpty().withMessage('UID required for session termination')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { uid, email, reason } = req.body;
    try {
        const userQuery = await pool.query('SELECT session_start_time, hostname, email FROM users WHERE firebase_uid = $1', [uid]);
        if (userQuery.rowCount > 0) {
            const { session_start_time, hostname, email } = userQuery.rows[0];
            const startTime = new Date(session_start_time);
            const durationMs = new Date() - startTime;
            const durationMins = Math.floor(durationMs / 60000);

            sendSecurityAlert('LOGOUT_EVENT', {
                user: email, uid: uid, duration: `${durationMins} minutes`,
                termination_reason: reason || 'User Manual Logout'
            });

            // --- NEW: REMOVE FROM ACTIVE HOSTNAMES ---
            const h = await resolveDashboardUserHostname(pool, uid, email, hostname);
            if (h) activeHostnames.delete(h);
            if (h && activeHostUserMap[h] === uid) delete activeHostUserMap[h];
            delete activeUserIpMap[req.ip];

            // Insert Logout into activity_logs for timeline
            await pool.query(
                'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
                [uid, 'logout', 'T1078', JSON.stringify({ duration: `${durationMins}m` }), req.ip, getDestIp(req)]
            );

            await pool.query('UPDATE users SET current_session_id = NULL WHERE firebase_uid = $1', [uid]);
        }
        res.json({ status: 'logged_out' });
    } catch (e) { res.status(500).send('Error'); }
});

// 3. ACTIVITY LOGGING ENDPOINT (War Games + All User Actions)
app.post('/api/log', [
    body('uid').notEmpty().withMessage('UID required'),
    body('action').notEmpty().withMessage('Action required'),
    body('details').optional().isObject().withMessage('Details must be an object')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { uid, action, details, sessionId } = req.body;
    const clientIp = req.ip;
    const destIp = getDestIp(req);

    try {
        // Short-window dedupe for repetitive frontend beacons.
        // Keep high-signal security events unsuppressed.
        const nonDedupActions = new Set([
            'login_fail',
            'sql_injection',
            'xss_attack',
            'unauthorized_face_detected',
            'brute_force'
        ]);
        if (!nonDedupActions.has(action)) {
            const dedupeWindowMs = action === 'internal_nav' ? 5000 : 2500;
            const dedupeKey = `${uid}:${action}:${JSON.stringify(details || {})}`;
            const nowMs = Date.now();
            const seenAt = activityLogDebounce[dedupeKey];
            if (seenAt && (nowMs - seenAt) < dedupeWindowMs) {
                return res.json({ status: 'deduped', reason: 'Repeated activity event suppressed' });
            }
            activityLogDebounce[dedupeKey] = nowMs;
        }

        // --- NEW: SESSION LIFECYCLE REFRESH ---
        // If the frontend reports a fresh session start, we update the timestamp 
        // used for log clipping (NormalUserDashboard "each tym" isolation).
        if (action === 'session_start') {
            await pool.query(
                `UPDATE users SET session_start_time = $1, current_session_id = $2 WHERE firebase_uid = $3`,
                [new Date(details.startTime || Date.now()), sessionId || null, uid]
            ).catch(e => console.warn('[SESSION REFRESH FAILED]', e));
        }

        // Try ML service classification first
        const features = {
            method: 'POST',
            path: '/api/log',
            status_code: 200,
            response_time_ms: 0,
            payload_size_bytes: JSON.stringify(details || {}).length,
            action_type: action || 'network_request',
        };
        const mlResult = await callMLService(features);
        const ruleResult = SIEMRuleEngine(action, details || {}, mlResult);

        const techniqueId = ruleResult.techniqueId;
        const anomalyScore = ruleResult.riskScore;
        const isAnomaly = ruleResult.isHighSeverity;

        if (isAnomaly || action === 'unauthorized_face_detected') {
            const alertType = action === 'unauthorized_face_detected' ? 'UNAUTHORIZED_PHYSICAL_ACCESS' : (action || 'ANOMALY').toUpperCase();
            console.log(`[ALERT TRIGGER] action=${action} uid=${uid} score=${anomalyScore.toFixed(3)} technique=${techniqueId}`);

            // 1. Send Email Alert
            sendSecurityAlert(alertType, { ...details, riskScore: anomalyScore, techniqueId, uid });

            // Record enterprise detection
            await recordDetection(pool, { uid, hostname: clientIp, techniqueId, anomalyScore, action: alertType, details: { ...details, method: 'api_log' } });
        }

        // Insert into activity_logs
        await pool.query(
            'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
            [uid, action, techniqueId, JSON.stringify({ ...details, ml_anomaly_score: anomalyScore, ml_is_anomaly: isAnomaly }), clientIp, destIp]
        );

        res.json({ status: 'logged', techniqueId, anomalyScore, isAnomaly });
    } catch (e) {
        console.error('[LOG ERROR]', e);
        res.status(500).send('Log failed');
    }
});

// --- 3.5 AGENT INGESTION ENDPOINT (ELITE AGENT) ---
/**
 * Route: POST /api/agent/log
 * Description: Ingests real-time telemetry from remote endpoint agents. 
 *              Includes high-entropy event analysis, MITRE ATT&CK mapping, 
 *              and multi-stage noise suppression (deduplication) for 
 *              repetitive system events like CPU spikes or app launches.
 * Parameters:
 *   - hostname (str): Originating machine identifier.
 *   - event_type (str): Category (AppBehaviour, DeviceControl, etc.).
 *   - user_id (str): UID for session isolation.
 *   - details (object): Raw metadata from the agent.
 * Returns:
 *   - JSON: { status: 'ok' } or error status.
 */
app.post('/api/agent/log', [
    // Purpose: Accept agent telemetry (Python/PowerShell/Elite agent variants), validate, normalize, store.
    // Input: JSON body (either Watchtower Elite format or simple demo OPEN/CLOSE payload).
    // Output: {status:'ok'} or validation/error response.
    body('hostname').optional().isString(),
    body('timestamp').optional().isString(),
    body('application_name').optional().isString(),
    body('event_type').optional().isString(),
    body('user_id').optional().isString(),
    body('user_action').optional().isString(),
    body('metadata').optional().isObject()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    // Accept both:
    // 1) Demo agent payload: {timestamp, application_name, event_type: OPEN|CLOSE, user_id, hostname}
    // 2) Elite payload: {timestamp, event_type, application_name, user_action, severity, source, metadata}
    const {
        timestamp,
        event_type: rawEventType,
        application_name,
        user_action: rawUserAction,
        severity,
        source,
        metadata,
        hostname: rawHostname,
        user_id
    } = req.body;

    // Normalize demo OPEN/CLOSE into existing schema (so dashboard queries keep working)
    const isDemoLifecycle = (rawEventType === 'OPEN' || rawEventType === 'CLOSE') && !!application_name;
    const event_type = isDemoLifecycle ? 'AppBehaviour' : rawEventType;
    const user_action = isDemoLifecycle ? rawEventType : rawUserAction;

    const resolvedHostname =
        (metadata && metadata.hostname) ||
        rawHostname ||
        req.body.hostname ||
        'UNKNOWN_HOST';

    if (!resolvedHostname || resolvedHostname === 'UNKNOWN_HOST') {
        return res.status(400).json({ error: 'Hostname required' });
    }
    if (!event_type || typeof event_type !== 'string') {
        return res.status(400).json({ error: 'event_type required' });
    }

    // --- REQUIRE ACTIVE SESSION FOR COLLECTION ---
    // Requirement: System logs must start to collect after login success alone.
    // We check if either the hostname is known to be active or the specific UID is active.
    const isHostActive = activeHostnames.has(resolvedHostname);
    const mappedUidForHost = activeHostUserMap[resolvedHostname] || null;
    const payloadUid = (user_id && user_id !== 'SYSTEM_AGENT') ? user_id : (metadata?.uid || metadata?.user_id || null);
    const effectiveUid = payloadUid || mappedUidForHost;
    const isUserActive = effectiveUid ? Array.from(Object.values(activeUserIpMap)).some(u => u.uid === effectiveUid) : false;

    if (!isHostActive && !isUserActive) {
        // console.log(`[AGENT] Dropping log from inactive source: host=${resolvedHostname} uid=${user_id}`);
        return res.status(200).json({ status: 'ignored', reason: 'Session not active' });
    }

    if (isDemoLifecycle) {
        if (!user_id || typeof user_id !== 'string') return res.status(400).json({ error: 'user_id required' });
        if (user_action !== 'OPEN' && user_action !== 'CLOSE') return res.status(400).json({ error: 'event_type must be OPEN or CLOSE' });
    }

    // --- DEBOUNCE LOGIC (NOISE REDUCTION) ---
    // Prevent spam if an app flickers or system sends duplicate events
    const logHostname = resolvedHostname;
    const logEventType = user_action || event_type || 'UNKNOWN';
    const normalizedAppName = String(application_name || metadata?.application_name || metadata?.process_name || 'unknown').trim().toLowerCase();

    // --- APP STATE TRANSITION GUARD ---
    // Accept only real OPEN->CLOSE transitions per host/app to suppress chatter.
    const isOpenEvent = (logEventType === 'OPEN' || logEventType === 'PROCESS_START' || logEventType === 'APPLICATION_STARTED');
    const isCloseEvent = (logEventType === 'CLOSE' || logEventType === 'PROCESS_STOP' || logEventType === 'APPLICATION_CLOSED');
    if (normalizedAppName !== 'unknown' && (isOpenEvent || isCloseEvent)) {
        if (!agentState[logHostname]) agentState[logHostname] = {};
        const prevState = agentState[logHostname][normalizedAppName] || 'CLOSED';
        if (isOpenEvent && prevState === 'OPEN') {
            return res.status(200).json({ status: 'deduped', reason: 'App already open (state guard)' });
        }
        if (isCloseEvent && prevState !== 'OPEN') {
            return res.status(200).json({ status: 'deduped', reason: 'Close without open (state guard)' });
        }
        agentState[logHostname][normalizedAppName] = isOpenEvent ? 'OPEN' : 'CLOSED';
    }

    // SIEM-Watchtower's own process (node.exe) — suppress for 5 minutes to avoid flooding
    const appNameLower = (application_name || '').toLowerCase();
    const isSelfLog = appNameLower.includes('node') || appNameLower.includes('siem') ||
        appNameLower.includes('watchtower') || appNameLower.includes('siem-watchtower');
    if (isSelfLog) {
        const selfKey = `${logHostname}:${application_name || 'unknown'}:${logEventType}`;
        if (agentLogDebounce[selfKey]) {
            return res.status(200).json({ status: 'deduped', reason: 'Self-log suppressed (5m window)' });
        }
        agentLogDebounce[selfKey] = true;
        setTimeout(() => delete agentLogDebounce[selfKey], 5 * 60 * 1000); // 5 minutes
    }

    // --- REPETITION SUPPRESSION ---
    // Prevent repetitive noisy events from slamming the DB
    if (logEventType === 'APP_STARTED' || logEventType === 'APP_STOPPED' ||
        logEventType === 'PROCESS_START' || logEventType === 'PROCESS_STOP' ||
        logEventType === 'OPEN' || logEventType === 'CLOSE' ||
        logEventType === 'WIFI_CONNECTED' || logEventType === 'WIFI_DISCONNECTED' ||
        logEventType === 'USER_LOGIN' || logEventType === 'USER_LOGOUT' ||
        logEventType === 'SCREEN_LOCKED' || logEventType === 'SCREEN_UNLOCKED' ||
        logEventType === 'LOGIN_SUCCESS' ||
        logEventType === 'SOFTWARE_INSTALLED' || logEventType === 'SOFTWARE_UNINSTALLED' ||
        logEventType === 'NETWORK_PORT_OPENED' || logEventType === 'NETWORK_PORT_CLOSED' ||
        logEventType === 'MOBILE_PHONE_CONNECTED' || logEventType === 'MOBILE_PHONE_DISCONNECTED' ||
        logEventType === 'CHARGER_PLUGGED_IN' || logEventType === 'CHARGER_UNPLUGGED') {
        const debounceKey = `${logHostname}:${application_name || 'unknown'}:${logEventType}`;

        // If we saw this exact event in the last 15 seconds, ignore it
        if (agentLogDebounce[debounceKey]) {
            return res.status(200).json({ status: 'deduped', reason: 'Repeated event suppressed (15s window)' });
        }

        // Set flag and clear after 15 seconds
        agentLogDebounce[debounceKey] = true;
        setTimeout(() => delete agentLogDebounce[debounceKey], 15000);
    }

    // HIGH_CPU_LOAD fires every poll cycle when CPU is elevated — suppress for 60 seconds
    if (logEventType === 'HIGH_CPU_LOAD') {
        const cpuKey = `${logHostname}:HIGH_CPU_LOAD`;
        if (agentLogDebounce[cpuKey]) {
            return res.status(200).json({ status: 'deduped', reason: 'HIGH_CPU_LOAD suppressed (60s window)' });
        }
        agentLogDebounce[cpuKey] = true;
        setTimeout(() => delete agentLogDebounce[cpuKey], 60000);
    }

    if (logEventType === 'APP_HIGH_BATTERY') {
        const battKey = `${logHostname}:${normalizedAppName}:APP_HIGH_BATTERY`;
        if (agentLogDebounce[battKey]) {
            return res.status(200).json({ status: 'deduped', reason: 'APP_HIGH_BATTERY suppressed (120s window)' });
        }
        agentLogDebounce[battKey] = true;
        setTimeout(() => delete agentLogDebounce[battKey], 120000);
    }

    // --- UPDATE BATTERY TRACKING FROM AGENT ---
    // Handle all battery-related events to keep batteryTracking accurate
    if (logEventType === 'BATTERY_CRITICAL' || logEventType === 'CHARGER_PLUGGED_IN' || logEventType === 'CHARGER_UNPLUGGED' || logEventType === 'BATTERY_STATUS') {
        const level = metadata?.level ?? metadata?.percent ?? metadata?.batteryPercent ?? batteryTracking[logHostname]?.level ?? null;
        // Determine charging status from event type or metadata
        let status = 'DISCHARGING';
        if (logEventType === 'CHARGER_PLUGGED_IN' || metadata?.charging === true) {
            status = 'PLUGGED_IN';
        } else if (logEventType === 'CHARGER_UNPLUGGED' || metadata?.charging === false) {
            status = 'DISCHARGING';
        } else if (batteryTracking[logHostname]?.status) {
            status = batteryTracking[logHostname].status;
        }
        
        // Only update if we have a valid level
        if (level !== null) {
            batteryTracking[logHostname] = {
                level: parseFloat(level),
                status,
                timestamp: new Date()
            };
            console.log(`[BATTERY] Updated ${logHostname}: ${level}% (${status})`);
        }
    }

    // Default fallback if older agent hits this (backward compatibility)
    // If incoming is old format (hostname, event_type, data), map it
    const logTimestamp = timestamp || new Date();

    const ruleResult = SIEMRuleEngine('AGENT_EVENT', { event_type, application_name, user_action, severity, metadata });
    let techniqueId = ruleResult.techniqueId;
    const isAnomaly = ruleResult.isHighSeverity;

    // Map Severity/Action to Alerts
    if (severity === 'CRITICAL' || isAnomaly) {
        const alertType = event_type === 'Security' ? 'BRUTE_FORCE' : (user_action || 'AGENT_ALERT').toUpperCase();
        sendSecurityAlert(alertType, {
            hostname: logHostname,
            app: application_name,
            action: logEventType,
            details: metadata
        });

        // Record enterprise detection from agent
        recordDetection(pool, {
            uid: (metadata && metadata.uid) || null,
            hostname: logHostname,
            techniqueId,
            anomalyScore: ruleResult.riskScore,
            action: alertType,
            details: { ...metadata, application_name, user_action, event_type }
        });
    }

    // --- MITRE MAPPING FOR ALL AGENT EVENT TYPES ---
    // User requested absolute logic: Map every detected log to its correct MITRE technique
    // for professional forensic context.
    techniqueId = 'T1204'; // Default: User Execution

    // DeviceControl — USB/Bluetooth/Mobile
    if (event_type === 'DeviceControl') {
        if (logEventType.includes('USB')) techniqueId = 'T1091'; // Removable Media
        if (logEventType.includes('BLUETOOTH')) techniqueId = 'T1091';
        if (logEventType.includes('MOBILE')) techniqueId = 'T1052'; // Exfil via Physical Medium
        if (logEventType.includes('AIRPLANE')) techniqueId = 'T1070'; // Defense Evasion
        if (logEventType === 'CHARGER_PLUGGED_IN' || logEventType === 'CHARGER_UNPLUGGED') techniqueId = 'T1120'; // Peripheral Device Discovery
    }

    // Authentication — Login, Logout, Screen Lock
    if (event_type === 'Authentication' || event_type === 'Security') {
        if (logEventType === 'LOGIN_SUCCESS') techniqueId = 'T1078'; // Valid Accounts
        if (logEventType === 'LOGIN_FAILED') techniqueId = 'T1110'; // Brute Force
        if (logEventType === 'USER_LOGOFF' || logEventType === 'USER_LOGOUT') techniqueId = 'T1078';
        if (logEventType === 'USER_LOGIN') techniqueId = 'T1078';
        if (logEventType === 'SCREEN_LOCKED') techniqueId = 'T1078';
        if (logEventType === 'SCREEN_UNLOCKED') techniqueId = 'T1078';
        if (logEventType === 'PRIVILEGED_LOGON') techniqueId = 'T1068'; // Exploitation for Privilege Escalation
    }

    // Network — Connectivity
    if (event_type === 'Network' || logEventType.includes('WIFI') || logEventType.includes('PORT')) {
        if (logEventType.includes('WIFI')) techniqueId = 'T1040'; // Network Sniffing
        if (logEventType.includes('PORT')) techniqueId = 'T1049'; // System Network Connections Discovery
        if (logEventType === 'CONNECTION_BLOCKED') techniqueId = 'T1071'; // Application Layer Protocol
    }

    // System Performance & Discovery
    if (event_type === 'SystemPerformance' || logEventType === 'APP_HIGH_MEMORY' || logEventType === 'APP_HIGH_BATTERY') {
        if (logEventType === 'HIGH_CPU_LOAD') techniqueId = 'T1499'; // Endpoint DoS
        if (logEventType === 'SYSTEM_STARTUP' || logEventType === 'SYSTEM_RESTART' || logEventType === 'SYSTEM_SHUTDOWN') techniqueId = 'T1529'; // System Shutdown/Reboot
        techniqueId = techniqueId === 'T1204' ? 'T1082' : techniqueId; // System Information Discovery
    }

    // App Lifecycle & Execution
    if (event_type === 'AppBehaviour' || event_type.startsWith('APPLICATION_') || event_type.startsWith('APP_')) {
        techniqueId = 'T1204'; // User Execution
        if (logEventType === 'APPLICATION_CRASH') techniqueId = 'T1070'; // Indicator Removal (via crash)
    }

    // Persistence & Management
    if (event_type === 'AccountManagement') {
        if (logEventType === 'USER_ACCOUNT_CREATED') techniqueId = 'T1136'; // Create Account
        if (logEventType === 'GROUP_MEMBER_ADDED') techniqueId = 'T1098'; // Account Manipulation
    }
    if (event_type === 'Persistence' || event_type === 'SoftwareManagement') {
        if (logEventType.includes('SERVICE')) techniqueId = 'T1543'; // Create or Modify System Process
        if (logEventType.includes('TASK')) techniqueId = 'T1053'; // Scheduled Task/Job
        if (logEventType.includes('SOFTWARE')) techniqueId = 'T1072'; // Software Deployment Tools
    }

    // Normalize lock/unlock names so existing dashboard filters can see these events.
    const storedEventType = (() => {
        const action = (logEventType || '').toUpperCase();
        if (event_type === 'Authentication' && action === 'SCREEN_LOCKED') return 'WORKSTATION_LOCK';
        if (event_type === 'Authentication' && action === 'SCREEN_UNLOCKED') return 'WORKSTATION_UNLOCK';
        if (action === 'USER_LOGIN') return 'USER_LOGIN';
        if (action === 'USER_LOGOUT' || action === 'USER_LOGOFF') return 'USER_LOGOFF';
        if (action === 'OPEN' || action === 'APPLICATION_STARTED') return 'APPLICATION_STARTED';
        if (action === 'CLOSE' || action === 'APPLICATION_CLOSED') return 'APPLICATION_CLOSED';
        return (logEventType === 'FOREGROUND_WINDOW_CHANGE' ? 'FOREGROUND_WINDOW_CHANGE' : (event_type || 'System'));
    })();

    // Store in DB
    // We map:
    // event_type -> mapped_technique_id (simplified for now, or use T-codes if known)
    // details -> { application_name, severity, source, metadata, user_action }

    const dbDetails = {
        application_name,
        severity,
        source: source || 'WATCHTOWER_ELITE_AGENT',
        // Used for user isolation in `/api/system-logs`
        user_id: user_id || metadata?.user_id || null,
        ...metadata,
        // After spread so agent metadata never overwrites normalized lifecycle action (OPEN/CLOSE/etc.).
        user_action: logEventType,
    };

    // --- MACHINE LEARNING ALGORITHM MAPPING ---
    // User requested ML to actively collect and map common system/USB logs.
    const sysFeatures = {
        method: 'SYS',
        path: '/' + (application_name || 'system'),
        status_code: severity === 'CRITICAL' ? 500 : (severity === 'WARN' ? 403 : 200),
        response_time_ms: 10,
        payload_size_bytes: JSON.stringify(dbDetails).length,
        action_type: logEventType,
        cpu_usage_pct: severity === 'CRITICAL' ? 95.0 : 5.0
    };

    const mlRes = await callMLService(sysFeatures);
    if (mlRes) {
        if (!techniqueId || techniqueId === 'T1204') techniqueId = mlRes.techniqueId;
        dbDetails.ml_anomaly_score = mlRes.anomalyScore;
        dbDetails.ml_confidence = mlRes.confidence;

        if (mlRes.isAnomaly) {
            console.warn(`[ML SYSTEM ALERT] Anomalous System/Device Event: ${logEventType} | score=${mlRes.anomalyScore}`);
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) VALUES ($1, $2, $3, $4)`,
                [logHostname, `ML Anomalous ${event_type}`, 'HIGH', techniqueId]
            );
            // Also record to triggered_detections for Threat Hunter visibility
            await recordDetection(pool, {
                uid: effectiveUid,
                hostname: logHostname,
                techniqueId: techniqueId || 'T1204',
                anomalyScore: mlRes.anomalyScore,
                action: `ML_ANOMALY_${event_type}`,
                details: { event_type, ml_score: mlRes.anomalyScore, ml_confidence: mlRes.confidence, hostname: logHostname }
            });
        }
    }

    // --- AUTONOMOUS SIEM LOG INTELLIGENCE (FREQUENCY DETECTOR) ---
    try {
        const recentFreqCheck = await pool.query(
            `SELECT COUNT(*) as freq FROM system_logs WHERE hostname = $1 AND event_type = $2 AND timestamp > NOW() - INTERVAL '5 minutes'`,
            [logHostname, event_type]
        );
        const freqCount = parseInt(recentFreqCheck.rows[0].freq);

        if (freqCount > 20) {
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                 SELECT $1::text, $2::text, 'HIGH', 'T1499'
                 WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1 AND alert_type = $2 AND timestamp > NOW() - INTERVAL '30 minutes')`,
                [logHostname, `ANOMALY_SPIKE: High Volume of ${event_type}`]
            );
            // Also record to triggered_detections for Threat Hunter visibility
            await recordDetection(pool, {
                uid: effectiveUid,
                hostname: logHostname,
                techniqueId: 'T1499',
                anomalyScore: 0.85,
                action: 'ANOMALY_SPIKE',
                details: { event_type, frequency: freqCount, threshold: 20, hostname: logHostname }
            });
        }

        if (event_type === 'DeviceControl' && logEventType?.includes('USB') && freqCount >= 3) {
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                 SELECT $1::text, 'Excessive USB Insertions Detected', 'MEDIUM', 'T1052'
                 WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1 AND alert_type = 'Excessive USB Insertions Detected' AND timestamp > NOW() - INTERVAL '30 minutes')`,
                [logHostname]
            );
            // Also record to triggered_detections for Threat Hunter visibility
            await recordDetection(pool, {
                uid: effectiveUid,
                hostname: logHostname,
                techniqueId: 'T1052',
                anomalyScore: 0.75,
                action: 'USB_EXCESS_INSERTIONS',
                details: { event_type, frequency: freqCount, threshold: 3, hostname: logHostname }
            });
        }

        if (event_type === 'AppBehaviour' && logEventType === 'PROCESS_START' && freqCount >= 10) {
            const title = dbDetails.title || '';
            if (classifyActivity(title) === 'unknown') {
                await pool.query(
                    `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                     SELECT $1::text, 'Unexpected Application Behaviour Spike', 'MEDIUM', 'T1204'
                     WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1 AND alert_type = 'Unexpected Application Behaviour Spike' AND timestamp > NOW() - INTERVAL '30 minutes')`,
                    [logHostname]
                );
                // Also record to triggered_detections for Threat Hunter visibility
                await recordDetection(pool, {
                    uid: effectiveUid,
                    hostname: logHostname,
                    techniqueId: 'T1204',
                    anomalyScore: 0.70,
                    action: 'APP_BEHAVIOUR_SPIKE',
                    details: { event_type, frequency: freqCount, threshold: 10, application: title, hostname: logHostname }
                });
            }
        }

        // --- NEW: CRITICAL ALERT TRIGGER ---
        if (severity === 'CRITICAL' || severity === 'HIGH') {
            sendSecurityAlert(`AGENT_${logEventType}`, { ...dbDetails, hostname: logHostname, techniqueId });
        }
    } catch (e) {
        console.error('[SIEM RULE ENGINE ERROR]', e);
    }

    const logUserUid = effectiveUid;

    try {
        // Final dedupe guard before DB write (protects against rapid retries/replays).
        const recentSame = await pool.query(
            `SELECT id
             FROM system_logs
             WHERE hostname = $1
               AND event_type = $2
               AND COALESCE(details->>'user_action', '') = $3
               AND COALESCE(details->>'application_name', '') = $4
               AND timestamp > NOW() - INTERVAL '3 seconds'
             LIMIT 1`,
            [logHostname, storedEventType, logEventType || '', application_name || '']
        );
        if (recentSame.rows.length > 0) {
            return res.status(200).json({ status: 'deduped', reason: 'Duplicate agent event suppressed (DB guard)' });
        }

        await pool.query(
            "INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
            [
                logTimestamp,
                logHostname,
                storedEventType,
                techniqueId,            // Enhanced mapping with ML
                JSON.stringify(dbDetails),
                logUserUid
            ]
        );
        res.status(200).json({ status: 'ok' });
    } catch (e) {
        console.error('[AGENT LOG ERROR]', e);
        try {
            // Fallback: keep a small rolling buffer for the live demo
            inMemoryAgentLogs.push({
                id: `mem_${Date.now()}`,
                timestamp: logTimestamp,
                hostname: logHostname,
                event_type: storedEventType,
                mapped_technique_id: techniqueId,
                details: dbDetails,
                user_id: logUserUid
            });
            if (inMemoryAgentLogs.length > 500) inMemoryAgentLogs.splice(0, inMemoryAgentLogs.length - 500);
            return res.status(200).json({ status: 'ok', storage: 'memory_fallback' });
        } catch (_) {
            // ignore
        }
        res.status(500).json({ error: 'Failed to ingest log' });
    }
});

// --- 3.6 ACTIVE RESPONSE: AGENT COMMANDS ---
// Admin triggers a command for an agent
app.post('/api/agent/command', requireAdminRequester, (req, res) => {
    const { hostname, command, params } = req.body;
    if (!hostname || typeof hostname !== 'string' || hostname.length > 255) {
        return res.status(400).json({ error: 'Valid hostname is required' });
    }
    if (!command || typeof command !== 'string' || !ADMIN_COMMAND_ALLOWLIST.has(command)) {
        return res.status(400).json({ error: `Invalid command. Allowed: ${Array.from(ADMIN_COMMAND_ALLOWLIST).join(', ')}` });
    }
    if (params !== undefined && (typeof params !== 'object' || Array.isArray(params) || params === null)) {
        return res.status(400).json({ error: 'params must be a JSON object when provided' });
    }

    if (!agentCommandQueue[hostname]) agentCommandQueue[hostname] = [];

    const cmdId = uuidv4();
    agentCommandQueue[hostname].push({ id: cmdId, command, params, timestamp: new Date() });

    console.log(`[REMOTE] Queued ${command} for ${hostname} (ID: ${cmdId})`);
    res.json({ status: 'queued', id: cmdId });
});

// Toggle Auto-Defend
app.post('/api/agent/auto-defend', requireAdminRequester, (req, res) => {
    if (!validBoolean(req.body.enabled)) {
        return res.status(400).json({ error: 'enabled must be boolean' });
    }
    autoDefendMode = req.body.enabled;
    console.log(`[SOC] Auto-Defend Mode: ${autoDefendMode ? 'ARMED' : 'DISARMED'}`);
    res.json({ enabled: autoDefendMode });
});

// User Reporting Endpoint
app.post('/api/user/report', (req, res) => {
    const { uid, details } = req.body;
    if (!uid || typeof uid !== 'string') {
        return res.status(400).json({ error: 'uid is required' });
    }
    if (details !== undefined && (typeof details !== 'object' || Array.isArray(details) || details === null)) {
        return res.status(400).json({ error: 'details must be an object' });
    }
    const clientIp = req.ip;

    pool.query(
        'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip) VALUES ($1, $2, $3, $4, $5)',
        [uid, 'USER_REPORT', 'T1204', JSON.stringify({ user_notified: true, ...details }), clientIp]
    )
        .then(() => {
            console.log(`[USER REPORT] Success from ${uid}`);
            res.json({ status: 'success' });
        })
        .catch(err => {
            console.error('[REPORT ERROR]', err);
            res.status(500).json({ error: 'Failed to submit report' });
        });
});

// --- ADVANCED EVENT-DRIVEN TAB SWITCH CORRELATION ENGINE ---
// Categorizes active foreground applications into high-level logical groupings aiding ML correlation heuristics on behavioral patterns
/**
 * Function: classifyActivity
 * Description: Categorizes active foreground applications into logical 
 *              groupings (e.g., 'browser', 'development tools') based on 
 *              window titles captured by the endpoint agents.
 * Parameters:
 *   - title (str): The raw window title of the focused application.
 * Returns:
 *   - str: A sanitized category string or 'unknown'.
 */
const classifyActivity = (title) => {
    if (!title) return 'unknown';
    const lower = title.toLowerCase();
    if (lower.includes('chrome') || lower.includes('firefox') || lower.includes('edge') || lower.includes('safari') || lower.includes('brave')) return 'browser';
    if (lower.includes('code') || lower.includes('studio') || lower.includes('intellij') || lower.includes('cursor') || lower.includes('terminal') || lower.includes('powershell')) return 'development tools';
    if (lower.includes('slack') || lower.includes('teams') || lower.includes('discord') || lower.includes('zoom')) return 'communication apps';
    if (lower.includes('settings') || lower.includes('explorer') || lower.includes('task manager')) return 'system';
    return 'unknown';
};

// Endpoint receiving granular frontend user attention shifts (tab away/return) mapping those gaps against backend system logs to deduce off-platform anomalous behaviour
app.post('/api/telemetry/tab-switch', async (req, res) => {
    const { uid, sessionId, event_type, timestamp } = req.body;
    if (!uid) return res.status(400).json({ error: 'uid required' });
    if (!sessionId || typeof sessionId !== 'string') return res.status(400).json({ error: 'sessionId required' });
    if (event_type !== 'TAB_SWITCH_AWAY' && event_type !== 'TAB_SWITCH_RETURN') {
        return res.status(400).json({ error: 'Invalid event_type' });
    }
    const rawTs = new Date(timestamp);
    if (!timestamp || Number.isNaN(rawTs.getTime())) {
        return res.status(400).json({ error: 'Valid timestamp required' });
    }

    try {
        // ENFORCE PRIVACY CONTROLS
        const userRes = await pool.query('SELECT consent_tracking, anonymize_logs FROM users WHERE firebase_uid = $1', [uid]);
        if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        const { consent_tracking, anonymize_logs } = userRes.rows[0];

        if (!consent_tracking) {
            return res.status(200).json({ status: 'ignored', reason: 'consent_tracking disabled' });
        }

        const logUid = anonymize_logs ? `ANON-${uid.substring(0, 8)}` : uid;
        const utcTimestamp = rawTs.toISOString(); // Time Normalization

        // Unified Schema Log
        await pool.query(
            `INSERT INTO raw_logs (event_type, timestamp, user_id, session_id, source, metadata) VALUES ($1, $2, $3, $4, $5, $6)`,
            [event_type, utcTimestamp, logUid, sessionId, 'frontend', JSON.stringify({ original_uid: anonymize_logs ? 'masked' : uid })]
        );

        // Session State Tracking
        if (event_type === 'TAB_SWITCH_AWAY') {
            activeTabSessions[uid] = { sessionId, awayStartTime: utcTimestamp };
            return res.json({ status: 'tracked_away' });
        }

        if (event_type === 'TAB_SWITCH_RETURN') {
            const sessionMatch = activeTabSessions[uid];
            if (!sessionMatch) {
                return res.status(200).json({ status: 'no_matching_away_event' }); // Prevent broken sessions
            }

            const awayStart = new Date(sessionMatch.awayStartTime);
            const returnTime = new Date(utcTimestamp);
            const durationMs = returnTime - awayStart;

            delete activeTabSessions[uid]; // Prevent overlapping sessions

            // Multi-Source Correlation: Query foreground changes within +/- 3 secs
            const agentLogs = await pool.query(`
                SELECT * FROM system_logs 
                WHERE event_type = 'AppBehaviour' 
                AND details->>'user_action' = 'FOREGROUND_WINDOW_CHANGE'
                AND timestamp >= $1::timestamp - INTERVAL '3 seconds'
                AND timestamp <= $1::timestamp + INTERVAL '3 seconds'
            `, [awayStart.toISOString()]);

            let matchedTitle = "[Limited Visibility - Foreground Agent Not Detected]";
            let classification = "unknown";
            let confidence = 0.0;
            let risk = 'LOW';
            let mitreId = null;

            if (agentLogs.rows.length > 0) {
                const closest = agentLogs.rows.reduce((prev, curr) => {
                    return (Math.abs(new Date(curr.timestamp) - awayStart) < Math.abs(new Date(prev.timestamp) - awayStart)) ? curr : prev;
                });

                matchedTitle = closest.details.title || "Unknown Window";
                classification = classifyActivity(matchedTitle);

                // Advanced Confidence Scoring
                const diffSecs = Math.abs(new Date(closest.timestamp) - awayStart) / 1000;
                let timeProximityScore = diffSecs <= 1 ? 0.5 : 0.3;
                let windowTitleMatchScore = 0.3; // Confirmed from Endpoint
                let durationSimilarityScore = 0.2; // Assuming high trust for this step

                confidence = timeProximityScore + windowTitleMatchScore + durationSimilarityScore;
            } else {
                // No agent data available - infer activity from duration patterns
                const durationSecs = Math.round(durationMs / 1000);
                classification = 'browser';
                confidence = 0.45; // Lower confidence since we're inferring
                
                if (durationMs < 10 * 1000) {
                    // Very short - likely just checking something
                    matchedTitle = "Quick Context Switch (< 10s)";
                    classification = 'system';
                } else if (durationMs < 60 * 1000) {
                    // Short duration - likely messaging or quick task
                    matchedTitle = "Brief External Activity (10s - 1min)";
                    classification = 'communication apps';
                } else if (durationMs < 5 * 60 * 1000) {
                    // Medium duration - likely browsing or reading
                    matchedTitle = "Extended Web Browsing (1-5min)";
                    classification = 'browser';
                } else if (durationMs < 15 * 60 * 1000) {
                    // Longer duration - focused work
                    matchedTitle = "Focused External Work (5-15min)";
                    classification = 'development tools';
                } else if (durationMs < 30 * 60 * 1000) {
                    // Very long - possible meeting or deep work
                    matchedTitle = "Deep Focus Session (15-30min)";
                    classification = 'communication apps';
                    risk = 'MEDIUM';
                } else {
                    // Extremely long - idle or unattended
                    matchedTitle = "Extended Away Period (> 30min)";
                    classification = 'unknown';
                    risk = 'MEDIUM';
                    mitreId = 'T1078';
                }
            }

            // Behavioral / Risk mapping for long idle periods
            if (durationMs > 30 * 60 * 1000 && !mitreId) {
                mitreId = 'T1078';
                risk = 'MEDIUM';
                matchedTitle = matchedTitle + " [Long Idle Period]";
            }

            // Generate Correlated Session
            await pool.query(
                `INSERT INTO correlated_sessions (user_id, session_id, start_time, end_time, duration_ms, activity, classification, confidence_score, risk_score, mapped_technique_id) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                [logUid, sessionId, awayStart.toISOString(), returnTime.toISOString(), durationMs, matchedTitle, classification, confidence, risk, mitreId]
            );

            // Output contextual human-readable log for the dashboard timeline
            const durationSecs = Math.round(durationMs / 1000);
            await pool.query(
                `INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, timestamp) 
                 VALUES ($1, $2, $3, $4, $5)`,
                [logUid, 'nav_context', 'T1592', JSON.stringify({
                    message: `User left SIEM Dashboard → Opened ${matchedTitle} (${durationSecs}s)`,
                    duration: durationMs,
                    source: 'SIEM Dashboard',
                    destination: matchedTitle
                }), returnTime.toISOString()]
            );

            return res.json({ status: 'correlated', confidence, classification, title: matchedTitle });
        }
        res.status(400).json({ error: 'Unknown event_type' });
    } catch (e) {
        console.error('[TELEMETRY ERROR]', e);
        res.status(500).json({ error: 'Processing failed' });
    }
});

app.get('/api/agent/auto-defend/status', (req, res) => {
    res.json({ enabled: autoDefendMode });
});

// Agents call this every 10-30s to see if they need to do something
/**
 * Route: GET /api/agent/poll/:hostname
 * Description: Endpoint for agents to retrieve pending administrative 
 *              commands (e.g., REMOTE_LOCK) queued by SOC operators. 
 *              Provides an at-least-once command delivery mechanism.
 * Parameters:
 *   - hostname (str): The identifier of the polling machine.
 * Returns:
 *   - JSON: { commands: Array }
 */
app.get('/api/agent/poll/:hostname', [
    param('hostname').isString().isLength({ min: 1, max: 255 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { hostname } = req.params;
    const commands = agentCommandQueue[hostname] || [];

    // Once polled, we clear the queue for simplicity (At-Least-Once delivery assume)
    agentCommandQueue[hostname] = [];

    res.json({ commands });
});

// Agents report back if the command worked
app.post('/api/agent/command-result', async (req, res) => {
    const { hostname, commandId, status, details } = req.body;
    if (!hostname || typeof hostname !== 'string') return res.status(400).json({ error: 'hostname required' });
    if (!commandId || typeof commandId !== 'string') return res.status(400).json({ error: 'commandId required' });
    if (!status || typeof status !== 'string') return res.status(400).json({ error: 'status required' });
    if (details !== undefined && (typeof details !== 'object' || Array.isArray(details) || details === null)) {
        return res.status(400).json({ error: 'details must be an object' });
    }
    console.log(`[REMOTE] Agent ${hostname} executed command ${commandId}: ${status}`);

    // Log as activity so SOC can see it in timeline
    await pool.query(
        'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip) VALUES ($1, $2, $3, $4, $5)',
        ['WATCHTOWER_AGENT', 'REMOTE_EXECUTION_RESULT', 'T1204', JSON.stringify({ hostname, status, details, commandId }), req.ip]
    ).catch(e => { });

    res.json({ received: true });
});

// NOTE: `/api/system-logs` is implemented later in this file.
// Keeping only one implementation avoids confusion and inconsistent filtering.

// --- 4. SYSTEM LOG INGESTION (NXLOG) ---
app.post('/api/system-logs', async (req, res) => {
    const log = req.body;
    // Expected NXLog JSON format: { "EventTime": "...", "Hostname": "...", "EventID": 4624, "Message": "..." }

    // --- REQUIRE ACTIVE SESSION FOR COLLECTION ---
    // Requirement: System logs must start to collect after login success alone.
    const h = log.Hostname || 'UNKNOWN_HOST';
    
    // Check if the specific user (if identified in NXLog) is active
    const nxlogUser = log.EventData?.User || log.User || null;
    const isUserActive = nxlogUser ? Array.from(Object.values(activeUserIpMap)).some(u => u.email === nxlogUser) : false;

    if (!activeHostnames.has(h) && !isUserActive) {
        // console.log(`[NXLOG] Dropping log from inactive source: host=${h} user=${nxlogUser}`);
        return res.status(200).json({ status: 'ignored', reason: 'Session not active' });
    }

    try {
        let eventType = log.event_type || 'UNKNOWN_EVENT';
        let techniqueId = log.mapped_technique_id || 'T1204'; // Default: User Execution

        // --- MAP WINDOWS EVENT IDs to Internal Types ---
        const eid = parseInt(log.EventID);

        // Security Events
        if (eid === 4624) { eventType = 'USER_LOGIN'; techniqueId = 'T1078'; }
        if (eid === 4625) { eventType = 'LOGIN_FAILED'; techniqueId = 'T1110'; }
        if (eid === 4800) { eventType = 'WORKSTATION_LOCK'; techniqueId = 'T1078'; }
        if (eid === 4801) { eventType = 'WORKSTATION_UNLOCK'; techniqueId = 'T1078'; }
        // Power Events (Startup/Shutdown)
        if (eid === 6005) { eventType = 'SYSTEM_STARTUP'; techniqueId = 'T1078'; } // System started
        if (eid === 6006) { eventType = 'SYSTEM_SHUTDOWN'; techniqueId = 'T1078'; } // System cleanly shutting down
        if (eid === 1074) { eventType = 'SHUTDOWN_INITIATED'; techniqueId = 'T1078'; } // User/Process initiated restart/shutdown
        if (eid === 41 || eid === 6008) { eventType = 'UNEXPECTED_SHUTDOWN'; techniqueId = 'T1078'; } // Crash or power loss

        // Sleep / Wake Events
        if (eid === 42) { eventType = 'SYSTEM_SLEEP'; techniqueId = 'T1542'; } // Entering Sleep
        if (eid === 1) {
            const provider = log.ProviderName || log.SourceName || '';
            if (provider === 'Microsoft-Windows-Power-Troubleshooter') {
                eventType = 'SYSTEM_WAKE';
                techniqueId = 'T1542';
            } else if (provider === 'Microsoft-Windows-Kernel-General') {
                eventType = 'SYSTEM_TIME_CHANGE';
                techniqueId = 'T1078'; // Time manipulation / System Change
            } else {
                eventType = 'SYSTEM_INFO_EVENT_1';
                techniqueId = 'T1204';
            }
        }

        // System Metrics (Custom Agent)
        if (eid === 9001) { eventType = 'PERFORMANCE_METRIC'; techniqueId = 'T1071'; }
        if (eid === 9002) {
            eventType = 'BATTERY_STATUS';
            techniqueId = 'T1499';

            // Enhance Battery Event with Status
            // Support both user's new script (Status, Battery) and old one (BatteryStatus, level)
            const rawStatus = log.Data.Status || log.Data.BatteryStatus;
            const level = log.Data.Battery || log.Data.level;

            // 1=Discharging, 2=AC, 6-9=Charging
            let statusText = 'UNKNOWN';
            if (rawStatus === 1) statusText = 'DISCHARGING';
            else if (rawStatus === 2) statusText = 'PLUGGED_IN';
            else if (rawStatus >= 6) statusText = 'CHARGING';

            log.Data.status_text = statusText;
            log.Data.level = level; // Standardize for frontend

            // Requirement: Descriptive battery log for demo
            eventType = 'BATTERY_STATUS';
            log.Message = `Battery Level: ${level}% (${statusText})`;
            
            if (statusText === 'PLUGGED_IN' || statusText === 'CHARGING') {
                eventType = 'BATTERY_CHARGING';
                log.Message = `System Charging: ${level}% (AC Power Detected)`;
            }
            if (level < 20 && statusText === 'DISCHARGING') {
                eventType = 'BATTERY_LOW_ALERT';
                log.Message = `CRITICAL: Battery Low (${level}%) — Please connect to power`;
            }
        }
        if (eid === 9003) { eventType = 'SYSTEM_POWER_STATE'; techniqueId = 'T1542'; }

        // Security - Account Lockout
        if (eid === 4740) { eventType = 'ACCOUNT_LOCKOUT'; techniqueId = 'T1078'; }
        if (eid === 9003) { eventType = 'SYSTEM_POWER_STATE'; techniqueId = 'T1542'; }

        // Security - Process Creation (4688) - includes target app tracking
        if (eid === 4688) {
            const proc = (log.Data && log.Data.NewProcessName) || (log.NewProcessName) || '';
            const procLower = proc.toLowerCase();
            const procBaseName = proc.split('\\').pop().replace('.exe', '').toLowerCase();

            if (procLower.includes('powershell') || procLower.includes('cmd.exe')) {
                eventType = 'SCRIPT_EXECUTION'; techniqueId = 'T1059';
            } else if (procLower.includes('excel.exe')) {
                eventType = 'APP_LAUNCH_EXCEL'; techniqueId = 'T1204';
            } else if (procLower.includes('winword.exe')) {
                eventType = 'APP_LAUNCH_WORD'; techniqueId = 'T1204';
            } else if (procLower.includes('notepad.exe') || procLower.includes('notepad++.exe')) {
                eventType = 'APP_LAUNCH_NOTEPAD'; techniqueId = 'T1204';
            } else {
                eventType = 'PROCESS_CREATION'; techniqueId = 'T1204';
            }

            // attach clean app name for dashboard display
            log.application_name = procBaseName;
        }

        // Security - Process Termination (4689)
        if (eid === 4689) {
            const proc = (log.Data && log.Data.ProcessName) || (log.ProcessName) || '';
            const procBaseName = proc.split('\\').pop().replace('.exe', '').toLowerCase();
            eventType = 'PROCESS_STOP';
            techniqueId = 'T1204';
            log.application_name = procBaseName;
        }

        // USB Device Connect (Security channel EventID 6416)
        if (eid === 6416) { eventType = 'USB_DEVICE_CONNECTED'; techniqueId = 'T1052'; }

        // USB Device Connect/Disconnect (DriverFrameworks channel)
        if (eid === 2003) { eventType = 'USB_DEVICE_CONNECTED'; techniqueId = 'T1052'; }
        if (eid === 2004) { eventType = 'USB_DEVICE_DISCONNECTED'; techniqueId = 'T1052'; }
        if (eid === 2100) { eventType = 'USB_DEVICE_ACTIVITY'; techniqueId = 'T1052'; }

        // Application Crash (Application channel EventID 1000)
        if (eid === 1000) {
            eventType = 'APPLICATION_CRASH';
            techniqueId = 'T1499';
            log.application_name = log.Data?.FaultingApplicationName || log.SourceName || 'UNKNOWN_APP';
        }

        // Generic Suspicious Keyword Detection in Message
        if (log.Message && (
            log.Message.toLowerCase().includes('malware') ||
            log.Message.toLowerCase().includes('attack') ||
            log.Message.toLowerCase().includes('virus') ||
            log.Message.toLowerCase().includes('trojan')
        )) {
            techniqueId = 'T1204'; // User Execution (or Generic Alert)
            if (!eventType.includes('FAIL')) eventType = `SUSPICIOUS_EVENT_${eid}`;
        }

        // --- NEW: SYSMON WEBSITE AND NETWORK TRACKING ---
        let domain = null;
        let destination_ip = null;
        let destination_port = null;
        let security_status = null;
        let username = null;
        let process_name = null;
        let risk_level = null;

        if (eid === 22) {
            eventType = 'DNS_QUERY';
            techniqueId = 'T1071'; // Application Layer Protocol
            domain = log.EventData?.QueryName;
            process_name = log.EventData?.Image;
            username = log.EventData?.User;
        }

        if (eid === 3) {
            eventType = 'NETWORK_CONNECTION';
            techniqueId = 'T1071';
            destination_ip = log.EventData?.DestinationIp;
            destination_port = parseInt(log.EventData?.DestinationPort);
            process_name = log.EventData?.Image;
            username = log.EventData?.User;

            // Security Classification (HTTP vs HTTPS)
            if (destination_port === 443) {
                security_status = 'SECURE (HTTPS)';
            } else if (destination_port === 80) {
                security_status = 'NOT SECURE (HTTP)';
            } else {
                security_status = `OTHER (${destination_port})`;
            }
        }

        // --- RISK SCORING & ALERT GENERATION ---
        if (eid === 3 || eid === 22) {
            if (security_status === 'SECURE (HTTPS)') risk_level = 'LOW';
            else if (security_status === 'NOT SECURE (HTTP)') risk_level = 'MEDIUM';

            const sensitiveKeywords = ['login', 'bank', 'payment', 'admin'];
            const phishingKeywords = ['free', 'gift', 'reward', 'crack'];
            const domainLower = (domain || '').toLowerCase();

            if (security_status === 'NOT SECURE (HTTP)' && sensitiveKeywords.some(k => domainLower.includes(k))) {
                risk_level = 'HIGH';
                // Rule 1: Insecure Sensitive Website Access
                await pool.query(
                    `INSERT INTO active_alerts (username, alert_type, severity, related_domain, mitre_technique_id) VALUES ($1, $2, $3, $4, $5)`,
                    [username || 'UNKNOWN', 'Insecure Sensitive Website Access', 'HIGH', domain, 'T1557']
                );
                // Also record to triggered_detections for Threat Hunter visibility
                await recordDetection(pool, {
                    uid: username || null,
                    hostname: log.Hostname || 'UNKNOWN_HOST',
                    techniqueId: 'T1557',
                    anomalyScore: 0.80,
                    action: 'INSECURE_SENSITIVE_ACCESS',
                    details: { domain, security_status, hostname: log.Hostname || 'UNKNOWN_HOST' }
                });
            }

            if (phishingKeywords.some(k => domainLower.includes(k))) {
                risk_level = 'HIGH';
                // Rule 3: Suspicious Phishing Domain Access
                await pool.query(
                    `INSERT INTO active_alerts (username, alert_type, severity, related_domain, mitre_technique_id) VALUES ($1, $2, $3, $4, $5)`,
                    [username || 'UNKNOWN', 'Suspicious Phishing Domain Access', 'HIGH', domain, 'T1566']
                );
                // Also record to triggered_detections for Threat Hunter visibility
                await recordDetection(pool, {
                    uid: username || null,
                    hostname: log.Hostname || 'UNKNOWN_HOST',
                    techniqueId: 'T1566',
                    anomalyScore: 0.85,
                    action: 'PHISHING_DOMAIN_ACCESS',
                    details: { domain, hostname: log.Hostname || 'UNKNOWN_HOST' }
                });
            }

            // Rule 2: Possible Reconnaissance Activity
            if (domain) {
                const reconCheck = await pool.query(
                    `SELECT COUNT(DISTINCT domain) as domain_count FROM system_logs WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION') AND timestamp > NOW() - INTERVAL '2 minutes' AND hostname = $1`,
                    [log.Hostname || 'UNKNOWN_HOST']
                );
                if (parseInt(reconCheck.rows[0].domain_count) > 10) {
                    const recentAlert = await pool.query(
                        `SELECT id FROM active_alerts WHERE alert_type = 'Possible Reconnaissance Activity' AND username = $1 AND timestamp > NOW() - INTERVAL '2 minutes' LIMIT 1`,
                        [username || 'UNKNOWN']
                    );
                    if (recentAlert.rows.length === 0) {
                        await pool.query(
                            `INSERT INTO active_alerts (username, alert_type, severity, related_domain, mitre_technique_id) VALUES ($1, $2, $3, $4, $5)`,
                            [username || 'UNKNOWN', 'Possible Reconnaissance Activity', 'MEDIUM', 'Multiple Domains', 'T1595']
                        );
                        // Also record to triggered_detections for Threat Hunter visibility
                        await recordDetection(pool, {
                            uid: username || null,
                            hostname: log.Hostname || 'UNKNOWN_HOST',
                            techniqueId: 'T1595',
                            anomalyScore: 0.70,
                            action: 'RECONNAISSANCE_ACTIVITY',
                            details: { domain_count: reconCheck.rows[0].domain_count, threshold: 10, hostname: log.Hostname || 'UNKNOWN_HOST' }
                        });
                    }
                }
            }
        }

        // Attach extra extracted details to the log JSON for raw lookup
        if (eid === 3 || eid === 22) {
            log.SysmonExtracted = { domain, destination_ip, destination_port, security_status, username, process_name, risk_level };
        }


        // --- DEDUPLICATION & NOISE FILTERING ---

        // 1. Filter Noisy Logon Types (Only keep Interactive/Remote/Unlock)
        if (eventType === 'USER_LOGIN') {
            const lType = log.Data && log.Data.LogonType ? parseInt(log.Data.LogonType) : 0;
            // Keep: 2=Interactive, 7=Unlock, 10=Remote, 11=Cached
            if (![2, 7, 10, 11].includes(lType)) {
                return res.json({ status: 'ignored', reason: `LogonType ${lType} filtered` });
            }
        }

        // 2. Global Short-Window Deduplication
        // INCREASED TO 5 MINUTES PER USER REQUEST
        let dedupWindow = "INTERVAL '5 minutes'";

        // Exceptions for extremely rapid events that still need sampling but not 5m gap
        if (eventType === 'PROCESS_CREATION' || eventType === 'PROCESS_START') {
            dedupWindow = "INTERVAL '10 seconds'"; // Still keep short for visibility of rapid process chains
        } else if (eventType === 'FOREGROUND_WINDOW_CHANGE') {
            dedupWindow = "INTERVAL '1 seconds'";
        } else if (eventType === 'LOGIN_FAILED') {
            dedupWindow = "INTERVAL '0 seconds'"; // NEVER deduplicate login failures - needed for brute force detection
        }

        // --- NEW: AUTONOMOUS SIEM LOG INTELLIGENCE (FREQUENCY DETECTOR) ---
        const recentFreqCheck = await pool.query(
            `SELECT COUNT(*) as freq FROM system_logs WHERE hostname = $1 AND event_type = $2 AND timestamp > NOW() - INTERVAL '5 minutes'`,
            [log.Hostname || 'UNKNOWN', eventType]
        );
        const freqCount = parseInt(recentFreqCheck.rows[0].freq);

        if (freqCount > 20) {
            risk_level = 'HIGH';
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                 SELECT $1::text, $2::text, 'HIGH', 'T1499'
                 WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1::text AND alert_type = $2::text AND timestamp > NOW() - INTERVAL '30 minutes')`,
                [log.Hostname || 'UNKNOWN', `ANOMALY_SPIKE: High Volume of ${eventType}`]
            );
            // Also record to triggered_detections for Threat Hunter visibility
            await recordDetection(pool, {
                uid: username || null,
                hostname: log.Hostname || 'UNKNOWN',
                techniqueId: 'T1499',
                anomalyScore: 0.85,
                action: 'ANOMALY_SPIKE',
                details: { event_type: eventType, frequency: freqCount, threshold: 20, hostname: log.Hostname || 'UNKNOWN' }
            });
        }

        // Brute Force Detection: Trigger after 3 failed login attempts (PIN/Password)
        // freqCount is previous events in 5min window, so >= 2 means this is the 3rd+ attempt
        if (eventType === 'LOGIN_FAILED' && freqCount >= 2) {
            risk_level = 'CRITICAL';
            console.log(`[BRUTE_FORCE_DETECT] EventID 4625 detected. freqCount=${freqCount}, hostname=${log.Hostname || 'UNKNOWN'}`);
            const alertMessage = `BRUTE FORCE ATTEMPT: ${freqCount + 1} failed Windows login attempts detected from host ${log.Hostname || 'UNKNOWN'}. Possible PIN/Password guessing attack.`;
            
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                 SELECT $1::text, 'Brute Force Attempt Detected', 'CRITICAL', 'T1110'
                 WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1::text AND alert_type = 'Brute Force Attempt Detected' AND timestamp > NOW() - INTERVAL '30 minutes')`,
                [log.Hostname || 'UNKNOWN']
            );
            
            // Record detection for Threat Hunter
            await recordDetection(pool, {
                uid: username || null,
                hostname: log.Hostname || 'UNKNOWN',
                techniqueId: 'T1110',
                anomalyScore: 0.95,
                action: 'BRUTE_FORCE_ATTEMPT',
                details: { event_type: eventType, frequency: freqCount, threshold: 3, hostname: log.Hostname || 'UNKNOWN', target: 'Windows Login' }
            });
            
            // Send email alert to all admins
            await notifyAllAdmins(
                'CRITICAL: Brute Force Attack Detected',
                alertMessage + `\n\nTimestamp: ${new Date().toISOString()}\nSource Host: ${log.Hostname || 'UNKNOWN'}\nTarget Account: ${username || 'Unknown User'}\nMITRE Technique: T1110 (Brute Force)`
            );
        }

        const logMsg = log.Message || log.Data?.Message || '';
        if (eventType === 'SYSTEM_INFO_EVENT_1' && logMsg.toLowerCase().includes('usb') && freqCount >= 3) {
            risk_level = 'MEDIUM';
            await pool.query(
                `INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
                 SELECT $1::text, 'Excessive USB Insertions Detected', 'MEDIUM', 'T1052'
                 WHERE NOT EXISTS (SELECT 1 FROM active_alerts WHERE username = $1::text AND alert_type = 'Excessive USB Insertions Detected' AND timestamp > NOW() - INTERVAL '30 minutes')`,
                [log.Hostname || 'UNKNOWN']
            );
            // Also record to triggered_detections for Threat Hunter visibility
            await recordDetection(pool, {
                uid: username || null,
                hostname: log.Hostname || 'UNKNOWN',
                techniqueId: 'T1052',
                anomalyScore: 0.75,
                action: 'USB_EXCESS_INSERTIONS',
                details: { event_type: eventType, frequency: freqCount, threshold: 3, hostname: log.Hostname || 'UNKNOWN' }
            });
        }

        // Check if same event type from same host happened just now
        const recentDup = await pool.query(
            `SELECT timestamp FROM system_logs WHERE hostname = $1 AND event_type = $2 AND timestamp > NOW() - ${dedupWindow} LIMIT 1`,
            [log.Hostname || 'UNKNOWN', eventType]
        );

        if (recentDup.rows.length > 0) {
            // Special Case: Allow Process Creation/Stop if it's a DIFFERENT process
            if (eventType === 'PROCESS_CREATION' || eventType === 'PROCESS_START' || eventType === 'PROCESS_STOP') {
                const recentLog = await pool.query(
                    `SELECT details FROM system_logs WHERE hostname = $1 AND event_type = $2 ORDER BY timestamp DESC LIMIT 1`,
                    [log.Hostname || 'UNKNOWN', eventType]
                );
                if (recentLog.rows.length > 0) {
                    const latest = recentLog.rows[0].details || {};
                    const prevProc = latest.NewProcessName || latest.application_name || latest.metadata?.title || latest.title || '';
                    const currProc = (log.Data && log.Data.NewProcessName) ? log.Data.NewProcessName : (log.application_name || log.metadata?.title || log.title || '');
                    if (prevProc === currProc) {
                        return res.json({ status: 'deduped', reason: 'Duplicate process event' });
                    }
                }
            } else if (eventType === 'FOREGROUND_WINDOW_CHANGE') {
                const recentLog = await pool.query(
                    `SELECT details FROM system_logs WHERE hostname = $1 AND event_type = 'FOREGROUND_WINDOW_CHANGE' ORDER BY timestamp DESC LIMIT 1`,
                    [log.Hostname || 'UNKNOWN']
                );
                if (recentLog.rows.length > 0) {
                    const prevTitle = recentLog.rows[0].details.metadata?.title || recentLog.rows[0].details.title || '';
                    const currTitle = log.Data.title || '';
                    if (prevTitle === currTitle) {
                        return res.json({ status: 'deduped', reason: 'Duplicate window event' });
                    }
                }
            } else {
                return res.json({ status: 'deduped', reason: `Duplicate event within window` });
            }
        }

        if (eventType === 'FIREWALL_BLOCK') {
            logStats.firewallBlocks++;
            // Only log 1 per minute per host to avoid spam
            const lastLog = await pool.query("SELECT timestamp FROM system_logs WHERE event_type = 'FIREWALL_BLOCK' AND hostname = $1 ORDER BY timestamp DESC LIMIT 1", [log.Hostname]);
            if (lastLog.rows.length > 0) {
                const diffMs = new Date() - new Date(lastLog.rows[0].timestamp);
                if (diffMs < 60000) return res.status(200).send('Deduped');
            }
        } else if (eventType === 'PERFORMANCE_METRIC') {
            logStats.perfHits++;
            perfTracking[log.Hostname] = {
                cpu: log.Data.cpu_load,
                ram_used: log.Data.ram_used_mb,
                ram_total: log.Data.ram_total_mb,
                timestamp: new Date()
            };
            // Return early to avoid DB spam if desired, or log samples occasionally
            // For now, let's log everything but maybe we can sample later
        } else if (eventType === 'BATTERY_STATUS' || eventType === 'BATTERY_CHARGING' || eventType === 'BATTERY_LOW') {
            batteryTracking[log.Hostname] = {
                level: log.Data.level,
                status: log.Data.status_text,
                timestamp: new Date()
            };
        } else {
            logStats.nxlogHits++;
        }

        const nxUid = activeHostUserMap[log.Hostname || 'UNKNOWN_HOST'] || null;

        // Insert into DB
        await pool.query(
            "INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details, domain, destination_ip, destination_port, security_status, risk_level, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            [
                log.EventTime || new Date(),
                log.Hostname || 'UNKNOWN_HOST',
                eventType,
                techniqueId,
                JSON.stringify(log), // Store full raw log for drilldown
                domain,
                destination_ip,
                destination_port,
                security_status,
                risk_level,
                nxUid
            ]
        );

        res.json({ status: 'ingested', type: eventType });
    } catch (e) {
        console.error('[NXLOG ERROR]', e);
        res.status(500).send('Ingest failed');
    }
});

// --- REPORTING ENDPOINTS ---
app.get('/api/reports/website-summary', requireAdminRequester, async (req, res) => {
    try {
        const totalVisitsRes = await pool.query(`SELECT COUNT(*) as count FROM system_logs WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION')`);
        const secureRes = await pool.query(`SELECT COUNT(*) as count FROM system_logs WHERE security_status = 'SECURE (HTTPS)'`);
        const insecureRes = await pool.query(`SELECT COUNT(*) as count FROM system_logs WHERE security_status = 'NOT SECURE (HTTP)'`);
        const highRiskRes = await pool.query(`SELECT COUNT(*) as count FROM system_logs WHERE risk_level = 'HIGH'`);

        const topDomainsRes = await pool.query(`
            SELECT domain, COUNT(*) as count FROM system_logs 
            WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION') AND domain IS NOT NULL
            GROUP BY domain ORDER BY count DESC LIMIT 5
        `);

        const totalAlertsRes = await pool.query(`SELECT COUNT(*) as count FROM active_alerts`);

        const topMitreRes = await pool.query(`
            SELECT mitre_technique_id, COUNT(*) as count FROM active_alerts 
            GROUP BY mitre_technique_id ORDER BY count DESC LIMIT 5
        `);

        const getActiveAlertsRes = await pool.query(`SELECT * FROM active_alerts ORDER BY timestamp DESC LIMIT 50`);
        const getAppLogsRes = await pool.query(`
            (SELECT hostname as user, details->>'SysmonExtracted' as sysmon, domain, security_status, risk_level, timestamp 
            FROM system_logs WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION'))
            UNION ALL
            (SELECT u.email as user, NULL as sysmon, 'Internal App' as domain, 
            CASE WHEN action_type = 'nav_away' THEN 'TAB_MINIMIZED' ELSE 'TAB_RESUMED' END as security_status, 
            'INFO' as risk_level, a.timestamp 
            FROM activity_logs a JOIN users u ON a.user_id = u.firebase_uid 
            WHERE a.action_type IN ('nav_away', 'nav_return'))
            ORDER BY timestamp DESC LIMIT 50
        `);

        res.json({
            total_web_visits: parseInt(totalVisitsRes.rows[0].count),
            secure_count: parseInt(secureRes.rows[0].count),
            insecure_count: parseInt(insecureRes.rows[0].count),
            high_risk_count: parseInt(highRiskRes.rows[0].count),
            top_5_domains: topDomainsRes.rows,
            total_alerts: parseInt(totalAlertsRes.rows[0].count),
            top_mitre_techniques: topMitreRes.rows,
            active_alerts: getActiveAlertsRes.rows,
            recent_logs: getAppLogsRes.rows.map(log => ({
                user: log.user,
                domain: log.domain,
                security_status: log.security_status,
                risk_level: log.risk_level,
                timestamp: log.timestamp
            }))
        });
    } catch (e) {
        console.error('[REPORT ERROR]', e);
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

// --- USER MANAGEMENT ROUTES ---
app.post('/api/promote', [
    body('uid').isString().notEmpty().withMessage('uid required'),
    body('requester_uid').isString().notEmpty().withMessage('requester_uid required')
], requireAdminRequester, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { uid, requester_uid } = req.body;
    try {
        const updateRes = await pool.query("UPDATE users SET role = 'ADMIN' WHERE firebase_uid = $1", [uid]);
        if (updateRes.rowCount === 0) return res.status(404).json({ error: 'Target user not found' });
        await pool.query(
            'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
            [requester_uid, 'promote_admin', 'T1098', JSON.stringify({ target_uid: uid }), req.ip, getDestIp(req)]
        );
        res.json({ status: 'promoted' });
    } catch (e) { res.status(500).send('Error'); }
});

app.post('/api/demote', [
    body('uid').isString().notEmpty().withMessage('uid required'),
    body('requester_uid').isString().notEmpty().withMessage('requester_uid required')
], requireAdminRequester, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { uid, requester_uid } = req.body;
    try {
        const updateRes = await pool.query("UPDATE users SET role = 'USER' WHERE firebase_uid = $1", [uid]);
        if (updateRes.rowCount === 0) return res.status(404).json({ error: 'Target user not found' });
        await pool.query(
            'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
            [requester_uid, 'demote_user', 'T1098', JSON.stringify({ target_uid: uid }), req.ip, getDestIp(req)]
        );
        res.json({ status: 'demoted' });
    } catch (e) { res.status(500).send('Error'); }
});

app.post('/api/delete-user', [
    body('uid').isString().notEmpty().withMessage('uid required'),
    body('requester_uid').isString().notEmpty().withMessage('requester_uid required'),
    body('target_email').optional().isEmail().withMessage('target_email must be valid')
], requireAdminRequester, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { uid, requester_uid, target_email } = req.body;
    try {
        if (uid.startsWith('sys-')) {
            // It's a system host, delete logs
            const hostname = uid.replace('sys-', '');
            if (!hostname.trim()) return res.status(400).json({ error: 'Invalid system hostname' });
            await pool.query("DELETE FROM system_logs WHERE hostname = $1", [hostname]);
        } else {
            // It's a normal user
            await pool.query(
                'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
                [requester_uid, 'delete_user', 'T1098', JSON.stringify({ target_uid: uid, target_email }), req.ip, getDestIp(req)]
            );
            await pool.query("DELETE FROM users WHERE firebase_uid = $1", [uid]);
        }
        res.json({ status: 'deleted' });
    } catch (e) { res.status(500).send('Error'); }
});

app.post('/api/change-password', [
    body('uid').isString().notEmpty().withMessage('uid required'),
    body('email').isEmail().withMessage('valid email required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { uid, email } = req.body;
    try {
        await pool.query(
            'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip) VALUES ($1, $2, $3, $4, $5, $6)',
            [uid, 'change_password', 'T1098', JSON.stringify({ email }), req.ip, getDestIp(req)]
        );
        res.json({ status: 'password_changed' });
    } catch (e) { res.status(500).send('Error'); }
});

// Privacy Updates
app.post('/api/user/privacy', async (req, res) => {
    const { uid, consent_tracking, anonymize_logs } = req.body;
    if (!uid || typeof uid !== 'string') return res.status(400).json({ error: 'uid required' });
    if (consent_tracking !== undefined && !validBoolean(consent_tracking)) {
        return res.status(400).json({ error: 'consent_tracking must be boolean' });
    }
    if (anonymize_logs !== undefined && !validBoolean(anonymize_logs)) {
        return res.status(400).json({ error: 'anonymize_logs must be boolean' });
    }
    try {
        if (consent_tracking !== undefined) {
            await pool.query('UPDATE users SET consent_tracking = $1 WHERE firebase_uid = $2', [consent_tracking, uid]);
        }
        if (anonymize_logs !== undefined) {
            await pool.query('UPDATE users SET anonymize_logs = $1 WHERE firebase_uid = $2', [anonymize_logs, uid]);
        }
        res.json({ status: 'updated' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/reports/correlated-sessions', requireAdminRequester, async (req, res) => {
    const limit = parseBoundedInt(req.query.limit, 50, 1, 500);
    try {
        const result = await pool.query(
            'SELECT * FROM correlated_sessions ORDER BY created_at DESC LIMIT $1',
            [limit]
        );
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- DASHBOARD DATA ENDPOINT ---
/**
 * Route: GET /api/dashboard-data
 * Description: Central data synchronization endpoint for the SOC frontend. 
 *              Aggregates role-based telemetry (personal for users, global 
 *              for admins) including threats, stats, heatmaps, and host logs.
 * Parameters:
 *   - uid (str): Requesters Firebase UID for role verification.
 * Returns:
 *   - JSON: Structured dashboard state object.
 */
app.get('/api/dashboard-data', async (req, res) => {
    const { uid } = req.query;
    if (!uid || typeof uid !== 'string' || !uid.trim()) return res.status(400).send("UID Required");

    try {
        // 1. IDENTIFY REQUESTER
        const userRes = await pool.query(
            'SELECT role, email, session_start_time, current_session_id, hostname FROM users WHERE firebase_uid = $1',
            [uid]
        );
        if (userRes.rows.length === 0) return res.status(404).send("User not found");

        const user = userRes.rows[0];
        const role = user.role || 'USER';
        const username = user.email.split('@')[0]; // Extract 'jdoe' from 'jdoe@example.com'
        const userHostname = await resolveDashboardUserHostname(pool, uid, user.email, user.hostname);

        // --- NORMAL USER DASHBOARD (Lite Version) ---
        if (role === 'USER' && user.email !== SUPER_ADMIN_EMAIL) {
            const { all_history } = req.query;
            const isViewingAll = all_history === 'true';

            // 1. Identify Activation & Session Points
            // Requirement:
            // - New users: only logs collected after their first login.
            // - Existing/legacy users: include historical logs as well.
            const activationRes = await pool.query(`
                SELECT MIN(timestamp) as start_point FROM activity_logs 
                WHERE user_id = $1 AND action_type = 'session_initiated'
            `, [uid]);

            const firstUserLogRes = await pool.query(`
                SELECT MIN(ts) AS first_seen
                FROM (
                    SELECT MIN(timestamp) AS ts FROM activity_logs WHERE user_id = $1
                    UNION ALL
                    SELECT MIN(timestamp) AS ts FROM system_logs WHERE user_id = $1
                ) t
            `, [uid]);

            const activationPoint =
                activationRes.rows[0]?.start_point ||
                firstUserLogRes.rows[0]?.first_seen ||
                user.session_start_time ||
                new Date();

            // Fetch Web Activity - Full history for the specific user (uid)
            // Isolated by user_id and clipped by activation point for new users.
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const webLogs = await pool.query(`
                SELECT action_type as type, details, timestamp, 'WEB' as source, mapped_technique_id
                FROM (
                    SELECT DISTINCT ON (timestamp, action_type, details::text)
                        action_type, details, timestamp, mapped_technique_id
                    FROM activity_logs
                    WHERE user_id = $1
                    AND user_id IS NOT NULL
                    AND action_type != 'create_user'
                    AND timestamp >= $2
                    ORDER BY timestamp DESC, action_type, details::text
                ) dedup
                ORDER BY timestamp DESC
                LIMIT 100
            `, [uid, activationPoint]);

            // Fetch System Activity - strict per-user isolation by user_id.
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const sysLogsQueryText = `
                SELECT event_type as type, details, timestamp, 'SYSTEM' as source, mapped_technique_id
                FROM (
                    SELECT DISTINCT ON (
                        timestamp,
                        event_type,
                        COALESCE(details->>'user_action', ''),
                        COALESCE(details->>'application_name', ''),
                        hostname
                    )
                        event_type, details, timestamp, mapped_technique_id, hostname
                    FROM system_logs
                    WHERE event_type IN (
                        'USER_LOGIN', 'USER_LOGOFF', 'LOGIN_FAILED',
                        'WORKSTATION_LOCK', 'WORKSTATION_UNLOCK',
                        'SCREEN_LOCKED', 'SCREEN_UNLOCKED',
                        'FOREGROUND_WINDOW_CHANGE', 'DeviceControl', 'AppBehaviour', 
                        'APPLICATION_STARTED', 'APPLICATION_CLOSED', 'Authentication',
                        'SystemPerformance'
                    )
                    AND user_id = $1
                    AND user_id IS NOT NULL
                    AND timestamp >= $2
                    ${isViewingAll ? '' : "AND timestamp > NOW() - INTERVAL '24 hours'"}
                    ORDER BY
                        timestamp DESC,
                        event_type,
                        COALESCE(details->>'user_action', ''),
                        COALESCE(details->>'application_name', ''),
                        hostname
                ) dedup
                ORDER BY timestamp DESC
                LIMIT 100
            `;

            const sysLogsParams = [uid, activationPoint];
            const sysLogs = await pool.query(sysLogsQueryText, sysLogsParams);

            // Merge & Sort
            let combinedActivity = [...webLogs.rows, ...sysLogs.rows];
            combinedActivity.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            combinedActivity = combinedActivity.slice(0, 100);

            // 2. Security Stats (Failed Logins)
            // Match against email OR username
            const failedLogins = await pool.query(`
                SELECT COUNT(*) FROM activity_logs 
                WHERE (details::jsonb->>'user' = $1 OR details::jsonb->>'user' = $2) 
                AND action_type IN ('login_fail', 'login_fail_bad_pass') 
                AND timestamp > NOW() - INTERVAL '7 days'
            `, [user.email, username]);

            // 3. Active Sessions (Is there a current session ID?)
            const activeSessionCount = user.current_session_id ? 1 : 0;

            // 4. Security Alerts - Filtered by user_id
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const personalThreats = await pool.query(`
                SELECT * FROM system_logs 
                WHERE (event_type LIKE '%FAIL%' OR event_type = 'BRUTE_FORCE')
                AND user_id = $1
                AND user_id IS NOT NULL
                AND timestamp > NOW() - INTERVAL '24 hours'
            `, [uid]);

            // 5. Device Fingerprint
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const fingerprintQuery = await pool.query(`
                SELECT details FROM activity_logs 
                WHERE user_id = $1 
                AND user_id IS NOT NULL
                AND action_type = 'device_fingerprint'
                ORDER BY timestamp DESC LIMIT 1
            `, [uid]);
            const fingerprint = fingerprintQuery.rows[0]?.details || null;

            // 6. Security Score Calculation (Fetch from enterprise threat_scores table)
            const threatScoreRes = await pool.query(`
                SELECT score, risk_level FROM threat_scores 
                WHERE entity_id = $1 AND entity_type = 'USER'
            `, [user.email]);

            let score = 100;
            let riskLevel = 'SECURE';

            if (threatScoreRes.rows.length > 0) {
                // Invert the score for the "Shield Score" (0 = perfect, 100 = critical risk)
                // If threat_score is 100 (Critical), Shield Score is 0.
                score = Math.max(0, 100 - parseInt(threatScoreRes.rows[0].score));
                riskLevel = threatScoreRes.rows[0].risk_level;
            }

            // 7. User System Data
            // Purpose: Provide SYSTEM_LOGS tab data for normal users.
            // Input: `uid` (required). Optional `user_id` for agent-based isolation in demos.
            // Output: userSystem.logs + userSystem.frequency for the requesting user only.
            const { user_id: requestedUserId } = req.query;

            // Density Chart: Show full 24h history for the workstation.
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const userSysFreqRes = await pool.query(`
                    SELECT EXTRACT(HOUR FROM timestamp) AS hour, COUNT(*) AS count
                    FROM system_logs
                    WHERE user_id = $1
                    AND user_id IS NOT NULL
                    AND timestamp >= $2
                    AND timestamp > NOW() - INTERVAL '24 hours'
                    GROUP BY hour
                    ORDER BY hour;
                `, [uid, activationPoint]);

            const userSystemLogsRes = await pool.query(`
                    SELECT * FROM system_logs
                    WHERE user_id = $1
                    AND user_id IS NOT NULL
                    AND event_type NOT IN ('SYSTEM_INFO_EVENT_1', 'AGENT_HEARTBEAT')
                    AND timestamp >= $2
                    ${isViewingAll ? '' : "AND timestamp > NOW() - INTERVAL '24 hours'"}
                    ORDER BY timestamp DESC
                    LIMIT 100;
                `, [uid, activationPoint]);

            const processFreqData = (rows) => {
                const fullDay = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
                rows.forEach(r => {
                    const h = parseInt(r.hour);
                    if (h >= 0 && h < 24) fullDay[h].count = parseInt(r.count);
                });
                return fullDay;
            };

            // 8. Heatmap Data (Specific to User)
            // STRICT ISOLATION: Only show logs explicitly belonging to this user
            const userHeatmapRes = await pool.query(`
                SELECT 
                    EXTRACT(HOUR FROM timestamp) as hour,
                    COUNT(*) as count
                FROM (
                    SELECT timestamp FROM activity_logs WHERE user_id = $1 AND user_id IS NOT NULL AND timestamp >= $2
                    UNION ALL
                    SELECT timestamp FROM system_logs WHERE user_id = $1 AND user_id IS NOT NULL AND timestamp >= $2
                ) combined
                GROUP BY hour
                ORDER BY hour ASC
            `, [uid, activationPoint]);

            return res.json({
                meta: { role: 'USER' },
                user: {
                    uid: uid,  // Pass Firebase UID so frontend exports work
                    email: user.email,
                    last_login: user.session_start_time,
                    active_sessions: activeSessionCount,
                    failed_login_count: parseInt(failedLogins.rows[0].count),
                    security_status: riskLevel,
                    security_score: score,
                    fingerprint: fingerprint
                },
                activity: combinedActivity,
                alerts: personalThreats.rows,
                heatmap: userHeatmapRes.rows,
                userSystem: {
                    logs: userSystemLogsRes.rows,
                    frequency: processFreqData(userSysFreqRes.rows)
                }
            });
        }





        // --- ADMIN DASHBOARD (Full Version) ---
        // Final sanity check: only allow ADMINs or the SUPER_ADMIN to proceed past this point
        if (role !== 'ADMIN' && user.email !== SUPER_ADMIN_EMAIL) {
            return res.status(403).json({ error: "Access Denied: Administrative privileges required for global telemetry." });
        }

        // 2. COUNTS (KPIs)
        const allUsersCount = await pool.query("SELECT COUNT(*) FROM users");
        const allHostsCount = await pool.query("SELECT COUNT(DISTINCT hostname) FROM system_logs WHERE timestamp > NOW() - INTERVAL '24 hours'");
        const totalUsers = parseInt(allUsersCount.rows[0].count) + parseInt(allHostsCount.rows[0].count);

        const webEventsCount = await pool.query('SELECT COUNT(*) FROM activity_logs');
        const sysEventsCount = await pool.query('SELECT COUNT(*) FROM system_logs');
        const totalEvents = parseInt(webEventsCount.rows[0].count) + parseInt(sysEventsCount.rows[0].count);

        // 3. THREATS - UPDATED TO INCLUDE ALL WAR GAMES ATTACKS
        // Fetch recent web threats
        const webThreatsRes = await pool.query(`
            SELECT a.*, 'WEB' as source, m.name as technique_name 
            FROM activity_logs a 
            LEFT JOIN mitre_definitions m ON a.mapped_technique_id = m.matrix_id 
            WHERE a.mapped_technique_id IN (
                'T1110',      -- Brute Force
                'T1098',      -- Account Manipulation
                'T1499',      -- Endpoint Denial of Service
                'T1190',      -- Exploit Public-Facing Application (SQLi)
                'T1059.007',  -- Cross-Site Scripting (XSS)
                'T1115',      -- Clipboard Data
                'T1592',      -- Gather Victim Host Information
                'T1071'       -- Application Layer Protocol
            )
            ORDER BY a.timestamp DESC LIMIT 50
        `);

        // Fetch recent system threats (Aggregated to prevent repeating firewall blocks)
        const sysThreatsRes = await pool.query(`
            SELECT DISTINCT ON (s.event_type, s.hostname) s.*, 'SYSTEM' as source, m.name as technique_name 
            FROM system_logs s 
            LEFT JOIN mitre_definitions m ON s.mapped_technique_id = m.matrix_id 
            WHERE (s.event_type LIKE '%FAIL%' OR s.mapped_technique_id = 'T1110' OR s.event_type = 'WORKSTATION_LOCK' OR s.event_type = 'FIREWALL_BLOCK')
            AND s.timestamp > NOW() - INTERVAL '24 hours'
            ORDER BY s.event_type, s.hostname, s.timestamp DESC
        `);

        // --- NEW: TOTAL THREAT COUNT (Uncapped) ---
        const threatCountQuery = await pool.query(`
            SELECT COUNT(*) FROM activity_logs 
            WHERE mapped_technique_id IN ('T1110','T1098','T1499','T1190','T1059.007','T1115','T1592','T1071')
            AND timestamp > NOW() - INTERVAL '24 hours'
        `);
        const webThreatCount = parseInt(threatCountQuery.rows[0].count);
        const sysThreatCount = sysThreatsRes.rowCount; // Already deduped by query

        let allThreats = [...webThreatsRes.rows, ...sysThreatsRes.rows];
        allThreats.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        const threatsCount = webThreatCount + sysThreatCount;

        // 4. USER LIST (WEB + SYSTEM)
        const webUsersQuery = await pool.query('SELECT firebase_uid, email, role, session_start_time, current_session_id FROM users');
        const webUsersList = webUsersQuery.rows.map(u => ({
            ...u,
            type: 'WEB',
            status: u.current_session_id ? 'online' : 'offline'
        }));

        const sysHostsQuery = `SELECT DISTINCT hostname, MAX(timestamp) as last_seen FROM system_logs WHERE timestamp > NOW() - INTERVAL '24 hours' GROUP BY hostname`;
        const sysHostsRes = await pool.query(sysHostsQuery);
        const activeHostsCount = sysHostsRes.rows.length;
        const sysHostsList = sysHostsRes.rows.map(h => ({
            firebase_uid: 'sys-' + h.hostname,
            email: h.hostname,
            role: 'AGENT',
            session_start_time: h.last_seen,
            type: 'HOST',
            status: 'online'
        }));

        const combinedUserList = [...webUsersList, ...sysHostsList];

        // 5. WEB LOGS (Recent Activity - Unified Browser & OS Context)
        const recentActivityRes = await pool.query(`
            SELECT DISTINCT ON (timestamp, action_type, details::text, user_email)
                timestamp, action_type, details, user_email
            FROM (
                (SELECT a.timestamp, a.action_type, a.details::jsonb AS details, u.email as user_email
                 FROM activity_logs a
                 LEFT JOIN users u ON a.user_id = u.firebase_uid)
                UNION ALL
                (SELECT s.timestamp, s.event_type as action_type, s.details::jsonb AS details, s.hostname as user_email
                 FROM system_logs s
                 WHERE s.event_type = 'FOREGROUND_WINDOW_CHANGE')
            ) merged
            ORDER BY timestamp DESC, action_type, details::text, user_email
            LIMIT 40
        `);

        // 6. MITRE COVERAGE
        const mitreRes = await pool.query(`
            SELECT mapped_technique_id as matrix_id, COUNT(*) as count 
            FROM system_logs 
            GROUP BY mapped_technique_id 
            UNION ALL 
            SELECT mapped_technique_id as matrix_id, COUNT(*) as count 
            FROM activity_logs 
            GROUP BY mapped_technique_id
        `);

        // 7. SECURITY INTENSITY HEATMAP (Weighted Risk Analytics)
        const heatmapRes = await pool.query(`
            SELECT 
                EXTRACT(HOUR FROM timestamp) as hour,
                SUM(CASE 
                    WHEN mapped_technique_id = 'T1190' THEN 25 -- SQLi (High)
                    WHEN mapped_technique_id = 'T1059.007' THEN 20 -- XSS (High)
                    WHEN mapped_technique_id = 'T1110' THEN 15 -- Brute Force (Med)
                    WHEN mapped_technique_id = 'T1098' THEN 10 -- Account Manipulation
                    WHEN mapped_technique_id IS NOT NULL THEN 5 -- Generic Technique
                    ELSE 1 -- Standard Traffic
                END) as count
            FROM (
                SELECT timestamp, mapped_technique_id FROM activity_logs WHERE timestamp >= NOW() - INTERVAL '24 hours'
                UNION ALL
                SELECT timestamp, mapped_technique_id FROM system_logs WHERE timestamp >= NOW() - INTERVAL '24 hours'
                UNION ALL
                SELECT timestamp, mapped_technique_id FROM network_logs WHERE timestamp >= NOW() - INTERVAL '24 hours'
            ) combined
            GROUP BY hour
            ORDER BY hour ASC
        `);

        // 8. TOP ENDPOINTS
        const topPathsRes = await pool.query(`
            SELECT path, COUNT(*) as count 
            FROM network_logs 
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY path 
            ORDER BY count DESC 
            LIMIT 10
        `);

        // 9. NEW: System Breakdown & Frequency
        const systemFreqQuery = await pool.query(`
            SELECT EXTRACT(HOUR FROM timestamp) AS hour, COUNT(*) AS count
            FROM system_logs
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY hour
            ORDER BY hour;
        `);

        const systemBreakdownQuery = await pool.query(`
            SELECT event_type, COUNT(*) AS count
            FROM system_logs
            WHERE timestamp > NOW() - INTERVAL '24 hours' AND event_type != 'SYSTEM_INFO_EVENT_1'
            GROUP BY event_type
            ORDER BY count DESC;
        `);

        const systemLogsQuery = await pool.query(`
            SELECT *
            FROM system_logs
            WHERE event_type != 'SYSTEM_INFO_EVENT_1'
            ORDER BY timestamp DESC
            LIMIT 50;
        `);

        const processSystemFreqData = (rows) => {
            const fullDay = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
            rows.forEach(r => {
                const h = parseInt(r.hour);
                if (h >= 0 && h < 24) fullDay[h].count = parseInt(r.count);
            });
            return fullDay;
        };

        const processBreakdownData = (rows) => {
            return rows.map(r => ({
                event_type: r.event_type,
                count: parseInt(r.count)
            }));
        };

        res.json({
            meta: { role: 'ADMIN' },
            stats: { users: totalUsers, events: totalEvents, threats: threatsCount },
            userList: combinedUserList,
            threatsList: allThreats,
            web: {
                heatmap: heatmapRes.rows,
                logs: recentActivityRes.rows,
                topPaths: topPathsRes.rows
            },
            system: {
                logs: systemLogsQuery.rows,
                frequency: processSystemFreqData(systemFreqQuery.rows),
                breakdown: processBreakdownData(systemBreakdownQuery.rows),
                activeHosts: activeHostsCount,
                battery: batteryTracking,
                performance: perfTracking,
                performanceHistory: (await pool.query(`
                    SELECT hostname, timestamp, details 
                    FROM system_logs 
                    WHERE event_type = 'PERFORMANCE_METRIC' 
                    AND timestamp > NOW() - INTERVAL '12 hours'
                    ORDER BY timestamp ASC
                `)).rows,
                powerEvents: (await pool.query(`
                    SELECT hostname, timestamp, event_type, details 
                    FROM system_logs 
                    WHERE event_type IN (
                        'SYSTEM_SLEEP', 'SYSTEM_WAKE', 'WORKSTATION_LOCK', 'WORKSTATION_UNLOCK', 'SYSTEM_BOOT',
                        'SCREEN_LOCKED', 'SCREEN_UNLOCKED', 'Authentication',
                        'SHUTDOWN_INITIATED', 'active_app_changed', 'process_start', 'process_stop', 
                        'power_source_ac', 'power_source_battery',
                        'DeviceControl', 'SystemPerformance', 'Security', 'AppBehaviour'
                    )
                    AND timestamp > NOW() - INTERVAL '24 hours'
                    ORDER BY timestamp DESC
                `)).rows
            },
            mitre: mitreRes.rows,
            radar: [],
            sankey: [] // Placeholder for future Sankey implementation
        });

    } catch (e) {
        console.error("Dashboard Error:", e);
        res.status(500).send("Server Error");
    }
});

// --- NEW: SIMULATION ALERT ENDPOINT ---
app.post('/api/alert/high-traffic', async (req, res) => {
    const { requestCount, duration, triggeredBy } = req.body;
    console.log(`[SIMULATION ALERT] ${triggeredBy}`);

    notifyAllAdmins('⚠️ DEFCON 3: High Traffic Alert',
        `TRAFFIC SPIKE DETECTED\n\nSource: ${triggeredBy}\nVolume: ${requestCount} requests\nDuration: ${duration}s\n\nAction: Investigate immediately.`);

    try {
        await pool.query(
            "INSERT INTO system_logs (event_type, details, hostname, mapped_technique_id, timestamp) VALUES ($1, $2, $3, $4, NOW())",
            ['TRAFFIC_SPIKE', JSON.stringify({ triggeredBy, count: requestCount, source_ip: '127.0.0.1' }), 'SIEM-SERVER', 'T1071']
        );
    } catch (e) { console.error("Sim Alert Log Failed:", e); }

    res.json({ status: 'alert_sent' });
});

/**
 * Route: GET /api/system-logs
 * Description: Retrieves historical system-level logs (Windows Events, Performance, 
 *              Device Control). Supports strict workspace isolation by 
 *              filtering data based on the requesting user's UID or agent ID.
 * Parameters:
 *   - uid (str): Firebase UID for filtering.
 *   - user_id (str): Agent-side user identifier.
 *   - limit (int): Maximum records to fetch.
 * Returns:
 *   - JSON: Array of normalized system log objects.
 */
app.get('/api/system-logs', async (req, res) => {
    // Purpose: Fetch recent system logs for dashboard (optionally isolated by user).
    // Input: Query params `uid` (firebase uid) and/or `user_id` (agent user id), optional `limit`.
    // Output: Array of system log rows (details parsed as object when possible).
    try {
        const { uid, user_id, limit, all_history, requester_uid } = req.query;
        const safeLimit = Math.max(1, Math.min(parseInt(limit || '100', 10) || 100, 200));
        const isViewingAll = all_history === 'true';

        // --- REQUIRE AUTH ---
        if (!uid && !user_id && !requester_uid) {
            return res.status(401).json({ error: "Authentication required (uid or requester_uid)" });
        }

        // Primary: Firebase uid → resolve PC hostname (matches agent system_logs.hostname)
        if (uid && typeof uid === 'string') {
            const ur = await pool.query(
                'SELECT email, hostname, role, session_start_time FROM users WHERE firebase_uid = $1 LIMIT 1',
                [uid]
            );
            if (ur.rows.length > 0) {
                const { email: uEmail, hostname: uHost, role } = ur.rows[0];
                const resolvedHost = await resolveDashboardUserHostname(pool, uid, uEmail, uHost);

                // --- IDENTIFY ACTIVATION POINT ---
                // For new users, clip to first successful session marker.
                // For existing/legacy users (without marker), keep their historical logs.
                const activationRes = await pool.query(`
                    SELECT MIN(timestamp) as start_point FROM activity_logs 
                    WHERE user_id = $1 AND action_type = 'session_initiated'
                `, [uid]);
                const firstUserLogRes = await pool.query(`
                    SELECT MIN(ts) AS first_seen
                    FROM (
                        SELECT MIN(timestamp) AS ts FROM activity_logs WHERE user_id = $1
                        UNION ALL
                        SELECT MIN(timestamp) AS ts FROM system_logs WHERE user_id = $1
                    ) t
                `, [uid]);
                const activationPoint =
                    activationRes.rows[0]?.start_point ||
                    firstUserLogRes.rows[0]?.first_seen ||
                    ur.rows[0].session_start_time ||
                    new Date();

                // We use the activation point for normal users to maintain isolation.
                // STRICT ISOLATION: Show logs explicitly belonging to this user OR from their hostname
                const result = await pool.query(
                    `
                    SELECT DISTINCT ON (
                        s.timestamp,
                        s.event_type,
                        COALESCE(s.details->>'user_action', ''),
                        COALESCE(s.details->>'application_name', ''),
                        s.hostname
                    ) s.*, m.name as technique_name
                    FROM system_logs s
                    LEFT JOIN mitre_definitions m ON s.mapped_technique_id = m.matrix_id
                    WHERE (
                        (s.user_id = $1 AND s.user_id IS NOT NULL)
                        OR 
                        (s.hostname = $4 AND s.user_id IS NULL)
                    )
                    AND s.timestamp >= $2
                    ${!isViewingAll && role === 'USER' && uEmail !== SUPER_ADMIN_EMAIL ? "AND s.timestamp > NOW() - INTERVAL '24 hours'" : ''}
                    ORDER BY
                        s.timestamp DESC,
                        s.event_type,
                        COALESCE(s.details->>'user_action', ''),
                        COALESCE(s.details->>'application_name', ''),
                        s.hostname
                    LIMIT $3
                    `,
                    [uid, activationPoint, safeLimit, resolvedHost]
                );
                return res.json(result.rows);
            }
        }

        // Agent stream id (e.g. SYSTEM_AGENT) when all telemetry shares the same user_id
        if (user_id && typeof user_id === 'string') {
            const result = await pool.query(
                `
                SELECT DISTINCT ON (s.timestamp, s.hostname, s.event_type)
                    s.*, m.name as technique_name
                FROM system_logs s
                LEFT JOIN mitre_definitions m ON s.mapped_technique_id = m.matrix_id
                WHERE (s.details::jsonb->>'user_id') = $1
                ORDER BY s.timestamp DESC, s.hostname, s.event_type
                LIMIT $2
                `,
                [user_id, safeLimit]
            );
            return res.json(result.rows);
        }

        // Backward compatible isolation (if logs embed uid inside details as metadata.uid)
        if (uid && typeof uid === 'string') {
            const result = await pool.query(
                `
                SELECT DISTINCT ON (s.timestamp, s.hostname, s.event_type)
                    s.*, m.name as technique_name
                FROM system_logs s
                LEFT JOIN mitre_definitions m ON s.mapped_technique_id = m.matrix_id
                WHERE (s.details::jsonb->>'uid') = $1 OR (s.details::jsonb->>'user_id') = $1
                ORDER BY s.timestamp DESC, s.hostname, s.event_type
                LIMIT $2
                `,
                [uid, safeLimit]
            );
            return res.json(result.rows);
        }

        // Default (admin / dev): no filtering - only if requester_uid is an admin
        if (requester_uid) {
            const adminRes = await pool.query('SELECT role FROM users WHERE firebase_uid = $1 LIMIT 1', [requester_uid]);
            if (!adminRes.rows.length || adminRes.rows[0].role !== 'ADMIN') {
                return res.status(403).json({ error: "Access Denied: Unfiltered telemetry access requires administrative privileges." });
            }

            const result = await pool.query(
                `
                SELECT DISTINCT ON (s.timestamp, s.hostname, s.event_type)
                    s.*, m.name as technique_name
                FROM system_logs s
                LEFT JOIN mitre_definitions m ON s.mapped_technique_id = m.matrix_id
                ORDER BY s.timestamp DESC, s.hostname, s.event_type
                LIMIT $1
                `,
                [safeLimit]
            );
            return res.json(result.rows);
        }

        res.status(403).json({ error: "Access Denied: User context required for isolated telemetry." });
    } catch (e) {
        console.error('[SYSTEM LOGS ERROR]', e);
        // Fallback for demo stability if DB is unavailable
        try {
            const { user_id, uid, limit } = req.query;
            const safeLimit = Math.max(1, Math.min(parseInt(limit || '100', 10) || 100, 200));
            const filterKey = (user_id || uid || '').toString();
            const filtered = filterKey
                ? inMemoryAgentLogs.filter(l => (l.details?.user_id === filterKey) || (l.details?.uid === filterKey)).slice(-safeLimit).reverse()
                : inMemoryAgentLogs.slice(-safeLimit).reverse();
            return res.json(filtered);
        } catch (_) {
            // ignore
        }
        res.status(500).json({ error: 'Failed to fetch system logs' });
    }
});

// --- MAINTENANCE: DEDUPLICATE LOGS ---
app.post('/api/maintenance/cleanup', requireAdminRequester, async (req, res) => {
    try {
        await pool.query(`
            DELETE FROM system_logs a USING (
                SELECT MIN(ctid) as ctid, timestamp, hostname, event_type
                FROM system_logs 
                GROUP BY timestamp, hostname, event_type
                HAVING COUNT(*) > 1
            ) b
            WHERE a.timestamp = b.timestamp 
            AND a.hostname = b.hostname 
            AND a.event_type = b.event_type 
            AND a.ctid <> b.ctid;
        `);
        console.log("[MAINTENANCE] Logs Deduplicated");
        res.json({ status: 'cleaned' });
    } catch (e) {
        console.error(e);
        res.status(500).send('Cleanup failed');
    }
});

app.get('/api/intel', requireAdminRequester, async (req, res) => {
    try { const result = await pool.query('SELECT * FROM mitre_definitions'); res.json(result.rows); }
    catch (e) { res.sendStatus(500); }
});

// --- 8. AUTOMATED ARCHIVAL (COLD STORAGE) ---
const { archiveOldLogs } = require('./archiver');

// Schedule: Run every 48 hours (in milliseconds)
const ARCHIVE_INTERVAL = 48 * 60 * 60 * 1000;

setInterval(async () => {
    console.log('[SCHEDULER] Triggering automated log archival...');
    try {
        const result = await archiveOldLogs(2); // Keep 2 days
        console.log('[SCHEDULER] Archival Result:', result);
    } catch (e) {
        console.error('[SCHEDULER] Archival Failed:', e);
    }
}, ARCHIVE_INTERVAL);

// Manual Trigger for Admin
app.post('/api/admin/force-archive', requireAdminRequester, async (req, res) => {
    const { days = 2 } = req.body;
    try {
        const result = await archiveOldLogs(days);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- 9. PANIC BUTTON ENDPOINT ---
app.post('/api/alert/panic', async (req, res) => {
    const { uid, email, reason } = req.body;
    console.log(`[PANIC] User ${email} reported incident: ${reason}`);

    try {
        // 1. Log as Critical Security Event
        await pool.query(
            'INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip) VALUES ($1, $2, $3, $4, $5)',
            [uid, 'USER_REPORTED_INCIDENT', 'T1600', JSON.stringify({ reason, email }), req.ip]
        );

        // 2. Send Alert Email (if configured)
        // sendSecurityAlert('USER_PANIC', { email, reason });

        res.json({ status: 'alerted', message: 'Security Team Notified' });
    } catch (e) {
        console.error('[PANIC ERROR]', e);
        res.status(500).json({ error: 'Failed to process panic alert' });
    }
});

// --- SIMPLE SOC DEMO ENDPOINT ---
const SIMPLE_DUMMY_LOGS = [
    { id: 1, timestamp: Date.now() - 100000, type: 'SYSTEM_STARTUP', hostname: 'DESKTOP-101', message: 'System booted' },
    { id: 2, timestamp: Date.now() - 90000, type: 'APP_INFO', hostname: 'DESKTOP-101', message: 'Service updated' },
    { id: 3, timestamp: Date.now() - 80000, type: 'APP_INFO', hostname: 'DESKTOP-101', message: 'Service updated' },
    { id: 4, timestamp: Date.now() - 79000, type: 'APP_INFO', hostname: 'DESKTOP-101', message: 'Service updated' },
    { id: 5, timestamp: Date.now() - 78000, type: 'APP_INFO', hostname: 'DESKTOP-101', message: 'Service updated' },
    { id: 6, timestamp: Date.now() - 50000, type: 'USB_CONNECTED', hostname: 'LAPTOP-202', message: 'Unknown Mass Storage' },
    { id: 7, timestamp: Date.now() - 48000, type: 'USB_REMOVED', hostname: 'LAPTOP-202', message: 'Mass Storage removed' },
    { id: 8, timestamp: Date.now() - 46000, type: 'USB_CONNECTED', hostname: 'LAPTOP-202', message: 'Unknown Mass Storage' },
    { id: 9, timestamp: Date.now() - 44000, type: 'USB_REMOVED', hostname: 'LAPTOP-202', message: 'Mass Storage removed' },
    { id: 10, timestamp: Date.now() - 20000, type: 'APP_ERROR', hostname: 'SERVER-01', message: 'DB Connection Timeout' },
    { id: 11, timestamp: Date.now() - 10000, type: 'SYSTEM_LOCK', hostname: 'DESKTOP-101', message: 'Screen locked' }
];

app.get('/api/simple-logs', (req, res) => {
    const processed = [];
    SIMPLE_DUMMY_LOGS.forEach(log => {
        const existingLog = processed.find(p => p.type === log.type && p.hostname === log.hostname);
        if (existingLog) {
            existingLog.count += 1;
            existingLog.timestamp = log.timestamp;
            if (existingLog.severity === 'LOW' && existingLog.count >= 3) {
                existingLog.severity = 'MEDIUM';
                existingLog.message = `${log.message} (Repeated)`;
            }
            if (existingLog.type.includes('USB') && existingLog.count >= 2) {
                existingLog.severity = 'HIGH';
                existingLog.message = 'Suspicious rapid USB switching detected';
            }
        } else {
            let baseSeverity = 'LOW';
            if (log.type.includes('WARNING')) baseSeverity = 'MEDIUM';
            if (log.type.includes('ERROR')) baseSeverity = 'HIGH';
            processed.push({ ...log, count: 1, severity: baseSeverity });
        }
    });
    res.json(processed.sort((a, b) => b.timestamp - a.timestamp));
});


// --- ENTERPRISE ROUTES ---
require('./enterprise_routes')(app, pool, requireAdminRequester);

// ─────────────────────────────────────────────────────────────────────────────
// /api/export  —  Download logs as CSV or JSON
// Query params:
//   table  : system_logs | network_logs | activity_logs   (required)
//   format : csv | json                                   (default: csv)
//   days   : 7 | 30 | 90 | all                           (default: 30)
//   uid    : firebase UID — filters activity_logs         (optional)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/export', async (req, res) => {
    let { table, format = 'csv', days = '30', uid } = req.query;

    // Sanitize uid: treat the literal strings 'undefined' or 'null' as absent
    if (uid === 'undefined' || uid === 'null' || uid === '') uid = null;

    // ── Whitelist allowed tables ───────────────────────────────────────────
    const ALLOWED_TABLES = ['system_logs', 'network_logs', 'activity_logs'];
    if (!ALLOWED_TABLES.includes(table)) {
        return res.status(400).json({ error: `Invalid table. Must be one of: ${ALLOWED_TABLES.join(', ')}` });
    }

    try {
        // ── Build query ────────────────────────────────────────────────────
        let queryText;
        let queryParams = [];

        // Time filter
        const dayFilter = days === 'all' ? null : parseInt(days) || 30;

        if (table === 'activity_logs') {
            // Activity logs can be filtered by uid (user dashboard) or global (admin)
            if (uid) {
                const anonymizedUid = `ANON-${uid.substring(0, 8)}`;
                queryText = `
                    SELECT id, user_id, action_type, mapped_technique_id, details, source_ip, destination_ip, timestamp
                    FROM activity_logs
                    WHERE (user_id = $1 OR user_id = $2)
                    ${dayFilter ? `AND timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                    ORDER BY timestamp DESC
                    LIMIT 10000`;
                queryParams = [uid, anonymizedUid];
            } else {
                queryText = `
                    SELECT al.id, u.email as user_email, al.user_id, al.action_type,
                           al.mapped_technique_id, al.details, al.source_ip, al.destination_ip, al.timestamp
                    FROM activity_logs al
                    LEFT JOIN users u ON al.user_id = u.firebase_uid
                    ${dayFilter ? `WHERE al.timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                    ORDER BY al.timestamp DESC
                    LIMIT 10000`;
            }
        } else if (table === 'system_logs') {
            queryText = `
                SELECT id, timestamp, hostname, event_type, mapped_technique_id,
                       domain, destination_ip, destination_port, security_status, risk_level, details
                FROM system_logs
                ${dayFilter ? `WHERE timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                ORDER BY timestamp DESC
                LIMIT 10000`;
        } else if (table === 'network_logs') {
            // network_logs table — fall back to system_logs network events if table doesn't exist
            try {
                queryText = `
                    SELECT *
                    FROM network_logs
                    ${dayFilter ? `WHERE timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                    ORDER BY timestamp DESC
                    LIMIT 10000`;
            } catch (_) {
                // Fallback: pull network events from system_logs
                queryText = `
                    SELECT id, timestamp, hostname, event_type, mapped_technique_id,
                           domain, destination_ip, destination_port, security_status, risk_level
                    FROM system_logs
                    WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION')
                    ${dayFilter ? `AND timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                    ORDER BY timestamp DESC
                    LIMIT 10000`;
            }
        }

        const result = await pool.query(queryText, queryParams);
        const rows = result.rows;

        const filename = `${table}_${days}d_${new Date().toISOString().split('T')[0]}`;

        // ── JSON export ────────────────────────────────────────────────────
        if (format === 'json') {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}.json"`);
            return res.json(rows);
        }

        // ── CSV export ─────────────────────────────────────────────────────
        if (rows.length === 0) {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
            return res.send('No data found for the selected range.\n');
        }

        // Build CSV header from first row's keys
        const headers = Object.keys(rows[0]);

        const escapeCsvCell = (val) => {
            if (val === null || val === undefined) return '';
            const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
            // Wrap in quotes if it contains comma, newline, or quote
            if (str.includes(',') || str.includes('\n') || str.includes('"')) {
                return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
        };

        const csvLines = [
            headers.join(','),
            ...rows.map(row => headers.map(h => escapeCsvCell(row[h])).join(','))
        ];

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
        return res.send(csvLines.join('\r\n'));

    } catch (e) {
        console.error('[EXPORT ERROR]', e.message);
        // If network_logs table doesn't exist, fall back to system_logs network events
        if (table === 'network_logs' && e.message.includes('does not exist')) {
            try {
                const dayFilter = days === 'all' ? null : parseInt(days) || 30;
                const fallback = await pool.query(`
                    SELECT id, timestamp, hostname, event_type, mapped_technique_id,
                           domain, destination_ip, destination_port, security_status, risk_level
                    FROM system_logs
                    WHERE event_type IN ('DNS_QUERY', 'NETWORK_CONNECTION')
                    ${dayFilter ? `AND timestamp > NOW() - INTERVAL '${dayFilter} days'` : ''}
                    ORDER BY timestamp DESC LIMIT 10000`);

                const filename = `network_logs_${days}d_${new Date().toISOString().split('T')[0]}`;
                if (format === 'json') {
                    res.setHeader('Content-Type', 'application/json');
                    res.setHeader('Content-Disposition', `attachment; filename="${filename}.json"`);
                    return res.json(fallback.rows);
                }
                const headers = fallback.rows.length ? Object.keys(fallback.rows[0]) : [];
                const escapeCsvCell = (val) => {
                    if (val === null || val === undefined) return '';
                    const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
                    if (str.includes(',') || str.includes('\n') || str.includes('"')) return `"${str.replace(/"/g, '""')}"`;
                    return str;
                };
                const csvLines = [headers.join(','), ...fallback.rows.map(row => headers.map(h => escapeCsvCell(row[h])).join(','))];
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', `attachment; filename="${filename}.csv"`);
                return res.send(csvLines.join('\r\n'));
            } catch (fe) {
                return res.status(500).json({ error: 'Export failed', detail: fe.message });
            }
        }
        return res.status(500).json({ error: 'Export failed', detail: e.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`[INFO] Process ID: ${process.pid}`);
    console.log(`[INFO] Archival Scheduler active (Every 48h). Logs older than 2 days will be moved to /logs/archive.`);
});

process.on('uncaughtException', (err) => console.error(err));
