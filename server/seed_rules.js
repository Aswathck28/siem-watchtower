/**
 * SIEM Watchtower — Seed Rules
 * Initial security detection rules mapped to MITRE ATT&CK framework.
 */

/**
 * Variable: INIT_RULES
 * Description: A static array of security detection rule objects used to populate the 
 *              system's initial heuristic knowledge base. Each rule includes MITRE mapping, 
 *              severity, and mitigation guidance.
 * Data Schema:
 *   - rule_name (str): Unique identifier for the detection rule.
 *   - description (str): Summary of the threat being detected.
 *   - severity (str): Threat level (CRITICAL, HIGH, MEDIUM, LOW).
 *   - mitre_id (str): Associated MITRE ATT&CK technique ID.
 *   - tactic (str): Associated MITRE ATT&CK tactic category.
 *   - confidence_score (int): Probability of the alert being a true positive (0-100).
 *   - trigger_reason (str): Logic or patterns that trigger the alert.
 *   - mitigation (str): Recommended administrative response steps.
 */
const INIT_RULES = [
    {
        rule_name: 'Brute Force Attempt',
        description: 'Multiple failed login attempts detected in a short time frame.',
        severity: 'HIGH',
        mitre_id: 'T1110',
        tactic: 'Credential Access',
        confidence_score: 90,
        trigger_reason: '5 or more failed login attempts within 5 minutes',
        mitigation: 'Enforce account lockout policies and require MFA. Review source IP for suspicious activity.'
    },
    {
        rule_name: 'Credential Stuffing',
        description: 'Large volume of login attempts from a single IP using different usernames.',
        severity: 'CRITICAL',
        mitre_id: 'T1110.004',
        tactic: 'Credential Access',
        confidence_score: 85,
        trigger_reason: 'Login attempts targeting multiple distinct accounts from the same source IP',
        mitigation: 'Implement rate limiting, deploy CAPTCHA, and enforce strong password policies.'
    },
    {
        rule_name: 'Impossible Travel',
        description: 'User logged in from geographically distant locations in an impossibly short timeframe.',
        severity: 'HIGH',
        mitre_id: 'T1078',
        tactic: 'Initial Access',
        confidence_score: 75,
        trigger_reason: 'Consecutive logins from distant IPs preventing physical travel',
        mitigation: 'Require step-up authentication (MFA) or block access if IP is an anonymizer/VPN.'
    },
    {
        rule_name: 'SQL Injection',
        description: 'Detection of SQL injection patterns in web requests or input fields.',
        severity: 'CRITICAL',
        mitre_id: 'T1190',
        tactic: 'Initial Access',
        confidence_score: 95,
        trigger_reason: 'Payload containing UNION SELECT, OR 1=1, or other SQLi signatures',
        mitigation: 'Use parameterized queries/prepared statements and deploy a Web Application Firewall (WAF).'
    },
    {
        rule_name: 'Cross-Site Scripting (XSS)',
        description: 'Malicious scripts injected into benign and trusted web sites.',
        severity: 'HIGH',
        mitre_id: 'T1059.007',
        tactic: 'Execution',
        confidence_score: 95,
        trigger_reason: 'Payload containing <script>, javascript:, or event handlers like onerror=',
        mitigation: 'Sanitize and encode all user inputs before rendering. Implement Content Security Policy (CSP).'
    },
    {
        rule_name: 'Path Traversal',
        description: 'Attempt to access unauthorized files or directories using path traversal techniques.',
        severity: 'HIGH',
        mitre_id: 'T1083',
        tactic: 'Discovery',
        confidence_score: 85,
        trigger_reason: 'Payload containing ../ or access to sensitive files like /etc/passwd',
        mitigation: 'Validate and sanitize file paths. Ensure application runs with least privilege.'
    },
    {
        rule_name: 'Suspicious PowerShell',
        description: 'Execution of PowerShell commands commonly used by attackers (e.g., encoded commands, bypass execution policy).',
        severity: 'CRITICAL',
        mitre_id: 'T1059.001',
        tactic: 'Execution',
        confidence_score: 80,
        trigger_reason: 'PowerShell execution with -enc, -ExecutionPolicy Bypass, or hidden window styles',
        mitigation: 'Enable Script Block Logging and turn on Constrained Language Mode.'
    },
    {
        rule_name: 'USB Device Abuse',
        description: 'Suspicious or unauthorized USB device connected to endpoint.',
        severity: 'MEDIUM',
        mitre_id: 'T1091',
        tactic: 'Initial Access',
        confidence_score: 70,
        trigger_reason: 'Mass storage device mounted on a restricted host',
        mitigation: 'Implement endpoint DLP policies and restrict USB mass storage.'
    },
    {
        rule_name: 'Port Scan',
        description: 'Rapid connection attempts to multiple distinct ports on a single host or across the network.',
        severity: 'MEDIUM',
        mitre_id: 'T1046',
        tactic: 'Discovery',
        confidence_score: 85,
        trigger_reason: 'High volume of connection attempts to varied ports within a small window',
        mitigation: 'Block source IP at edge firewall and investigate internal compromised hosts.'
    },
    {
        rule_name: 'DDoS-like Spike',
        description: 'Sudden massive spike in requests targeting specific endpoints.',
        severity: 'HIGH',
        mitre_id: 'T1498',
        tactic: 'Impact',
        confidence_score: 90,
        trigger_reason: 'Volumetric traffic spike exceeding normal baseline by 10x',
        mitigation: 'Enable rate limiting and utilize Edge/WAF DDoS protection services.'
    },
    {
        rule_name: 'Privilege Escalation',
        description: 'User or process attempting to inappropriately raise its security context.',
        severity: 'CRITICAL',
        mitre_id: 'T1068',
        tactic: 'Privilege Escalation',
        confidence_score: 80,
        trigger_reason: 'Unauthorized use of sudo, modification of admin groups, or service manipulation',
        mitigation: 'Enforce least privilege, monitor admin group changes, and alert on sensitive token modifications.'
    },
    {
        rule_name: 'Mass File Deletion',
        description: 'An unusually large number of files deleted in a short period.',
        severity: 'HIGH',
        mitre_id: 'T1485',
        tactic: 'Impact',
        confidence_score: 95,
        trigger_reason: 'Threshold crossed for concurrent or rapid file deletion actions',
        mitigation: 'Halt process, isolate host, and trigger backup recovery protocols.'
    },
    {
        rule_name: 'Session Hijacking',
        description: 'Use of stolen session tokens to masquerade as an authenticated user.',
        severity: 'CRITICAL',
        mitre_id: 'T1550',
        tactic: 'Credential Access',
        confidence_score: 65,
        trigger_reason: 'Session token presented from a wildly different IP/Device fingerprint simultaneously',
        mitigation: 'Invalidate all sessions for the user and force password reset.'
    },
    {
        rule_name: 'Ransomware-like Activity',
        description: 'High rate of file modifications/encryption with known ransomware extensions or ransom notes.',
        severity: 'CRITICAL',
        mitre_id: 'T1486',
        tactic: 'Impact',
        confidence_score: 98,
        trigger_reason: 'File system events showing rapid WRITE operations accompanied by extension changes',
        mitigation: 'Immediately isolate endpoint from network, shut down compromised services, invoke IR plan.'
    },
    {
        rule_name: 'Suspicious Admin Activity',
        description: 'Unusual actions performed by an administrative account, such as mass configuration changes.',
        severity: 'HIGH',
        mitre_id: 'T1078.002',
        tactic: 'Defense Evasion',
        confidence_score: 75,
        trigger_reason: 'Domain Admin account used on non-standard endpoints or outside normal hours',
        mitigation: 'Review admin audit logs and implement privileged access management (PAM).'
    }
];

/**
 * Function: seedRules
 * Description: An administrative utility function that resets the 'detection_rules' table 
 *              and populates it with the hardcoded 'INIT_RULES' dataset. It ensures 
 *              the database table structure exists before insertion.
 * Parameters:
 *   - pool (pg.Pool): The PostgreSQL connection pool.
 * Returns:
 *   - Promise<void>: Resolves when seeding is completed. Outputs progress to console.
 */
module.exports = async function seedRules(pool) {
    console.log('[SEED] Cleaning and refreshing detection rules...');
    
    // Ensure table structure is accurate first
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
        ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS trigger_reason TEXT;
    `);

    // Use DELETE instead of TRUNCATE to avoid foreign key constraint issues
    // and avoid locking conflicts with concurrent reads
    try {
        await pool.query('DELETE FROM detection_rules;');
    } catch (e) {
        console.error('[SEED] Failed to clear detection_rules', e);
    }

    let inserted = 0;
    for (const rule of INIT_RULES) {
        try {
            await pool.query(`
                INSERT INTO detection_rules (rule_name, description, severity, mitre_id, tactic, confidence_score, trigger_reason, mitigation, is_active)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
            `, [
                rule.rule_name,
                rule.description,
                rule.severity,
                rule.mitre_id,
                rule.tactic,
                rule.confidence_score,
                rule.trigger_reason,
                rule.mitigation
            ]);
            inserted++;
        } catch (e) {
            console.error(`[SEED] Failed to seed rule: ${rule.rule_name}`, e);
        }
    }
    
    console.log(`[SEED] Refresh complete. ${inserted} rules active.`);
};
