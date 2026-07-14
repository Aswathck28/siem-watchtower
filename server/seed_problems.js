require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'siem-watchtower',
    password: process.env.DB_PASS || 'pava4484',
    port: process.env.DB_PORT || 5432,
});

/**
 * Function: seed
 * Description: Populates the SIEM Watchtower relational schema with 
 *              synthetic mock threats, security alerts, and network 
 *              telemetry. Used during demonstrations to showcase 
 *              dashboard visualizations for SQL injection, brute 
 *              force, and application crashes.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise: Resolves with successful seeding or caught SQL error.
 */
async function seed() {
    try {
        console.log("Seeding fake threats into the database for UI Demonstration...");
        
        await pool.query(`
            INSERT INTO activity_logs (user_id, action_type, mapped_technique_id, details, source_ip, destination_ip)
            VALUES 
            ('admin_user', 'sql_injection', 'T1190', '{"path": "/query?id=1=1"}', '192.168.0.5', '127.0.0.1'),
            ('admin_user', 'sql_injection', 'T1190', '{"path": "/query?id=DROP TABLE"}', '192.168.0.5', '127.0.0.1'),
            ('unknown_actor', 'brute_force', 'T1110', '{"login": "admin"}', '45.33.22.1', '127.0.0.1'),
            ('unknown_actor', 'brute_force', 'T1110', '{"login": "admin"}', '45.33.22.1', '127.0.0.1'),
            ('unknown_actor', 'brute_force', 'T1110', '{"login": "admin"}', '45.33.22.1', '127.0.0.1'),
            ('system_agent', 'application_error', 'T1499', '{"message": "Critical Crash", "screenshot": "data:image/jpeg;base64,fakedata"}', '127.0.0.1', '127.0.0.1'),
            ('system_agent', 'application_error', 'T1499', '{"message": "Heap Corruption", "screenshot": "data:image/jpeg;base64,fakedata"}', '127.0.0.1', '127.0.0.1'),
            ('hacker', 'xss_attack', 'T1059.007', '{"payload": "<script>alert(1)</script>"}', '192.168.1.100', '127.0.0.1'),
            ('hacker', 'path_traversal', 'T1083', '{"path": "../../../etc/passwd"}', '192.168.1.100', '127.0.0.1');
        `);
        
        await pool.query(`
            INSERT INTO network_logs (method, path, status_code, response_time_ms, payload_size_bytes, source_ip, mapped_technique_id, anomaly_score, is_anomaly)
            VALUES
            ('POST', '/login', 401, 150, 45, '45.33.22.1', 'T1110', 0.85, true),
            ('POST', '/login', 401, 150, 45, '45.33.22.1', 'T1110', 0.85, true),
            ('GET', '/search?q=1=1', 500, 300, 150, '192.168.0.5', 'T1190', 0.95, true),
            ('POST', '/app', 500, 50, 0, '127.0.0.1', 'T1499', 0.99, true);
        `);
        
        await pool.query(`
            INSERT INTO correlated_sessions (user_id, session_id, start_time, end_time, duration_ms, activity, classification, confidence_score, risk_score, mapped_technique_id)
            VALUES 
            ('admin_user', 'sess_123', NOW(), NOW(), 5000, 'Multiple Failed Logins', 'system', 0.9, 'HIGH', 'T1110'),
            ('unknown', 'sess_456', NOW(), NOW(), 1200, 'SQL Injection Payload', 'browser', 0.95, 'HIGH', 'T1190'),
            ('agent', 'sess_789', NOW(), NOW(), 100, 'App Crashed (Screenshot Included)', 'system', 0.99, 'HIGH', 'T1499');
        `);

        await pool.query(`
            INSERT INTO active_alerts (username, alert_type, severity, mitre_technique_id) 
            VALUES 
            ('system_agent', 'APPLICATION_ERROR', 'CRITICAL', 'T1499'),
            ('admin', 'SQL_INJECTION', 'CRITICAL', 'T1190'),
            ('unknown', 'BRUTE_FORCE', 'HIGH', 'T1110');
        `);
        
        console.log("Successfully seeded issues to MITRE Framework!");
    } catch (e) {
        console.log("SQL Error: ", e.message);
    } finally {
        pool.end();
    }
}

seed();
