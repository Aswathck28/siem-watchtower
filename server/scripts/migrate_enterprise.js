/**
 * SIEM Watchtower - Enterprise DB Migration
 * Adds: detection_rules, triggered_detections, threat_scores, suspicious_ips, device_history
 */
require('dotenv').config({ path: '../.env' });
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'siem-watchtower',
  password: process.env.DB_PASS || 'pava4484',
  port: process.env.DB_PORT || 5432,
});

async function migrate() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    console.log('[MIGRATION] Starting enterprise upgrade migration...');

    // 1. DETECTION RULES TABLE
    await client.query(`
      CREATE TABLE IF NOT EXISTS detection_rules (
        id SERIAL PRIMARY KEY,
        rule_name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        severity VARCHAR(20) DEFAULT 'MEDIUM' CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
        mitre_id VARCHAR(30),
        tactic VARCHAR(100),
        trigger_condition TEXT,
        mitigation TEXT,
        confidence_score INTEGER DEFAULT 75 CHECK (confidence_score BETWEEN 0 AND 100),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
      CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre ON detection_rules(mitre_id);
    `);
    console.log('[MIGRATION] ✅ detection_rules table ready');

    // 2. TRIGGERED DETECTIONS TABLE
    await client.query(`
      CREATE TABLE IF NOT EXISTS triggered_detections (
        id SERIAL PRIMARY KEY,
        rule_id INTEGER REFERENCES detection_rules(id),
        rule_name VARCHAR(100),
        severity VARCHAR(20),
        mitre_id VARCHAR(30),
        hostname VARCHAR(255),
        user_id VARCHAR(100),
        source_ip VARCHAR(50),
        evidence JSONB,
        trigger_reason TEXT,
        confidence_score INTEGER,
        mitigation TEXT,
        acknowledged BOOLEAN DEFAULT FALSE,
        acknowledged_by VARCHAR(100),
        acknowledged_at TIMESTAMPTZ,
        timestamp TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_triggered_timestamp ON triggered_detections(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_triggered_severity ON triggered_detections(severity);
      CREATE INDEX IF NOT EXISTS idx_triggered_acknowledged ON triggered_detections(acknowledged);
      CREATE INDEX IF NOT EXISTS idx_triggered_hostname ON triggered_detections(hostname);
    `);
    console.log('[MIGRATION] ✅ triggered_detections table ready');

    // 3. THREAT SCORES TABLE
    await client.query(`
      CREATE TABLE IF NOT EXISTS threat_scores (
        id SERIAL PRIMARY KEY,
        entity_id VARCHAR(255) UNIQUE NOT NULL,
        entity_type VARCHAR(20) DEFAULT 'HOST' CHECK (entity_type IN ('HOST','USER','IP')),
        score INTEGER DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
        risk_level VARCHAR(20) DEFAULT 'LOW' CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
        factors JSONB DEFAULT '[]',
        last_updated TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_threat_scores_score ON threat_scores(score DESC);
      CREATE INDEX IF NOT EXISTS idx_threat_scores_entity ON threat_scores(entity_id);
    `);
    console.log('[MIGRATION] ✅ threat_scores table ready');

    // 4. SUSPICIOUS IPS TABLE
    await client.query(`
      CREATE TABLE IF NOT EXISTS suspicious_ips (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(50) UNIQUE NOT NULL,
        reason TEXT,
        country VARCHAR(100),
        first_seen TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        hit_count INTEGER DEFAULT 1,
        is_blocked BOOLEAN DEFAULT FALSE,
        severity VARCHAR(20) DEFAULT 'MEDIUM'
      );
      CREATE INDEX IF NOT EXISTS idx_suspicious_ip ON suspicious_ips(ip);
    `);
    console.log('[MIGRATION] ✅ suspicious_ips table ready');

    // 5. DEVICE HISTORY TABLE
    await client.query(`
      CREATE TABLE IF NOT EXISTS device_history (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(100),
        device_fingerprint VARCHAR(255),
        browser VARCHAR(100),
        os VARCHAR(100),
        ip_address VARCHAR(50),
        first_seen TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        is_trusted BOOLEAN DEFAULT FALSE,
        UNIQUE(user_id, device_fingerprint)
      );
      CREATE INDEX IF NOT EXISTS idx_device_user ON device_history(user_id);
    `);
    console.log('[MIGRATION] ✅ device_history table ready');

    // 6. SEED DETECTION RULES
    const rules = [
      {
        rule_name: 'BRUTE_FORCE_LOGIN',
        description: 'Multiple failed login attempts from the same IP within a short window',
        severity: 'HIGH',
        mitre_id: 'T1110',
        tactic: 'Credential Access',
        trigger_condition: 'More than 5 failed logins within 5 minutes from same IP',
        mitigation: 'Block source IP, enforce CAPTCHA, notify user, enable MFA',
        confidence_score: 90
      },
      {
        rule_name: 'CREDENTIAL_STUFFING',
        description: 'Multiple failed logins targeting different accounts from same IP',
        severity: 'CRITICAL',
        mitre_id: 'T1110.004',
        tactic: 'Credential Access',
        trigger_condition: 'Failed logins for 3+ different usernames from same IP in 10 minutes',
        mitigation: 'Block IP, rotate credentials, check for leaked databases',
        confidence_score: 88
      },
      {
        rule_name: 'SUSPICIOUS_LOGIN_HOURS',
        description: 'Login attempt outside of normal business hours (midnight to 5AM)',
        severity: 'MEDIUM',
        mitre_id: 'T1078',
        tactic: 'Defense Evasion',
        trigger_condition: 'Successful login between 00:00 and 05:00 local time',
        mitigation: 'Alert user, enforce time-based access controls, verify via MFA',
        confidence_score: 70
      },
      {
        rule_name: 'USB_RAPID_CYCLE',
        description: 'USB device inserted and removed repeatedly in a short window — possible data exfiltration',
        severity: 'HIGH',
        mitre_id: 'T1052.001',
        tactic: 'Exfiltration',
        trigger_condition: 'USB connected/disconnected 3+ times within 2 minutes',
        mitigation: 'Disable USB ports, quarantine device, review files accessed',
        confidence_score: 85
      },
      {
        rule_name: 'PROCESS_INJECTION_ATTEMPT',
        description: 'Suspicious known malware process name detected running on endpoint',
        severity: 'CRITICAL',
        mitre_id: 'T1055',
        tactic: 'Privilege Escalation',
        trigger_condition: 'Process name matches known malware signatures (mimikatz, nc.exe, netcat, etc.)',
        mitigation: 'Isolate host, kill process, run AV scan, investigate memory',
        confidence_score: 95
      },
      {
        rule_name: 'POWERSHELL_ABUSE',
        description: 'PowerShell executed with suspicious flags or encoded commands',
        severity: 'HIGH',
        mitre_id: 'T1059.001',
        tactic: 'Execution',
        trigger_condition: 'PowerShell launched with -EncodedCommand, -WindowStyle Hidden, or bypass flags',
        mitigation: 'Enable PowerShell script block logging, restrict execution policy, investigate command history',
        confidence_score: 88
      },
      {
        rule_name: 'ADMIN_PRIVILEGE_ABUSE',
        description: 'Non-admin user account added to privileged group',
        severity: 'CRITICAL',
        mitre_id: 'T1098',
        tactic: 'Persistence',
        trigger_condition: 'EventID 4728 or 4732 — user added to privileged/admin group',
        mitigation: 'Revert group membership, audit who performed change, review PAM policies',
        confidence_score: 92
      },
      {
        rule_name: 'MASS_FILE_DELETION',
        description: 'Large number of files deleted in rapid succession — possible ransomware',
        severity: 'CRITICAL',
        mitre_id: 'T1485',
        tactic: 'Impact',
        trigger_condition: 'More than 50 file delete events within 2 minutes on same host',
        mitigation: 'Isolate host immediately, restore from backup, run ransomware detection scan',
        confidence_score: 93
      },
      {
        rule_name: 'PORT_SCAN_DETECTED',
        description: 'Single IP connecting to many different ports — port scanning behavior',
        severity: 'HIGH',
        mitre_id: 'T1046',
        tactic: 'Discovery',
        trigger_condition: 'Same source IP connects to 20+ different ports within 1 minute',
        mitigation: 'Block source IP, update firewall rules, review exposed services',
        confidence_score: 86
      },
      {
        rule_name: 'DDOS_TRAFFIC_SPIKE',
        description: 'Abnormally high request volume from multiple sources targeting single endpoint',
        severity: 'CRITICAL',
        mitre_id: 'T1499',
        tactic: 'Impact',
        trigger_condition: 'More than 1000 requests to same API endpoint within 1 minute',
        mitigation: 'Enable rate limiting, activate CDN protection, block offending IP ranges',
        confidence_score: 80
      },
      {
        rule_name: 'ACCOUNT_LOCKOUT',
        description: 'User account locked out due to excessive failed authentication attempts',
        severity: 'MEDIUM',
        mitre_id: 'T1110',
        tactic: 'Credential Access',
        trigger_condition: 'Account lockout event (EventID 4740) detected',
        mitigation: 'Notify user, investigate source IP, review failed attempts',
        confidence_score: 95
      },
      {
        rule_name: 'NEW_DEVICE_LOGIN',
        description: 'User logged in from a browser/device not seen before',
        severity: 'MEDIUM',
        mitre_id: 'T1078',
        tactic: 'Initial Access',
        trigger_condition: 'Login from device fingerprint not in device_history for this user',
        mitigation: 'Send confirmation email, require MFA for new device',
        confidence_score: 75
      },
      {
        rule_name: 'SESSION_HIJACKING_INDICATOR',
        description: 'Active session IP or user-agent changed mid-session without re-authentication',
        severity: 'HIGH',
        mitre_id: 'T1563',
        tactic: 'Lateral Movement',
        trigger_condition: 'Session IP or user-agent changed while session is active',
        mitigation: 'Terminate session, force re-login, investigate token theft',
        confidence_score: 82
      },
      {
        rule_name: 'API_ABUSE',
        description: 'Excessive API calls from single user or IP — possible automated scraping or abuse',
        severity: 'MEDIUM',
        mitre_id: 'T1190',
        tactic: 'Initial Access',
        trigger_condition: 'More than 500 API calls from same user/IP per minute',
        mitigation: 'Apply rate limiting, block abusive token, review API keys',
        confidence_score: 78
      },
      {
        rule_name: 'SENSITIVE_PAGE_REPEATED_ACCESS',
        description: 'User repeatedly accessing sensitive admin/config pages in a short time',
        severity: 'MEDIUM',
        mitre_id: 'T1087',
        tactic: 'Discovery',
        trigger_condition: 'Same user accesses admin-level pages more than 10 times in 5 minutes',
        mitigation: 'Alert admin, review user intent, apply role-based access controls',
        confidence_score: 72
      },
      {
        rule_name: 'SQL_INJECTION_ATTEMPT',
        description: 'SQL injection payload detected in request parameter',
        severity: 'CRITICAL',
        mitre_id: 'T1190',
        tactic: 'Initial Access',
        trigger_condition: 'Request contains SQL keywords: UNION SELECT, DROP TABLE, OR 1=1, etc.',
        mitigation: 'Block request, log attacker IP, sanitize all inputs, use parameterized queries',
        confidence_score: 97
      },
      {
        rule_name: 'XSS_ATTACK_ATTEMPT',
        description: 'Cross-site scripting payload detected in request',
        severity: 'HIGH',
        mitre_id: 'T1059.007',
        tactic: 'Execution',
        trigger_condition: 'Request contains <script>, onerror=, javascript: tags',
        mitigation: 'Block request, encode output, implement Content Security Policy',
        confidence_score: 94
      },
      {
        rule_name: 'MULTIPLE_CONCURRENT_SESSIONS',
        description: 'Same user account logged in from multiple locations simultaneously',
        severity: 'MEDIUM',
        mitre_id: 'T1078',
        tactic: 'Defense Evasion',
        trigger_condition: 'More than 2 active sessions for same user_id at the same time',
        mitigation: 'Force logout oldest session, alert user, enforce single-session policy',
        confidence_score: 80
      },
      {
        rule_name: 'UNAUTHORIZED_ADMIN_ACTION',
        description: 'Non-admin account attempted to perform admin-level operations',
        severity: 'HIGH',
        mitre_id: 'T1548',
        tactic: 'Privilege Escalation',
        trigger_condition: 'User with ROLE=USER calling admin-only API endpoints',
        mitigation: 'Block action, log attempt, review account permissions',
        confidence_score: 90
      },
      {
        rule_name: 'EXCESSIVE_DATA_DOWNLOAD',
        description: 'Large volume of data exported or downloaded in a short timeframe',
        severity: 'HIGH',
        mitre_id: 'T1530',
        tactic: 'Exfiltration',
        trigger_condition: 'User downloads more than 100MB or exports more than 1000 records in 10 minutes',
        mitigation: 'Alert admin, throttle downloads, review what data was accessed',
        confidence_score: 77
      }
    ];

    for (const rule of rules) {
      await client.query(`
        INSERT INTO detection_rules (rule_name, description, severity, mitre_id, tactic, trigger_condition, mitigation, confidence_score)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (rule_name) DO UPDATE SET
          description = EXCLUDED.description,
          severity = EXCLUDED.severity,
          mitigation = EXCLUDED.mitigation,
          confidence_score = EXCLUDED.confidence_score
      `, [rule.rule_name, rule.description, rule.severity, rule.mitre_id, rule.tactic, rule.trigger_condition, rule.mitigation, rule.confidence_score]);
    }
    console.log(`[MIGRATION] ✅ Seeded ${rules.length} detection rules`);

    await client.query('COMMIT');
    console.log('\n[MIGRATION] 🎉 Enterprise upgrade migration complete!');
    console.log('[MIGRATION] Tables created: detection_rules, triggered_detections, threat_scores, suspicious_ips, device_history');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[MIGRATION] ❌ Failed:', err.message);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate().catch(console.error);
