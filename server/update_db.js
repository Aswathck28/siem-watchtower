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
 * Function: run
 * Description: Orchestrates cumulative schema migrations for the 
 *              SIEM Watchtower PostgreSQL database. Handles column 
 *              additions (e.g., risk_level), creation of archival 
 *              log tables, and initialization of the audit trail for 
 *              maintenance runs.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise: Resolves with successful database migration.
 */
async function run() {
  try {
    await pool.query(`
            ALTER TABLE system_logs 
            ADD COLUMN IF NOT EXISTS risk_level VARCHAR(50);
        `);
    console.log("Added risk_level to system_logs.");

    await pool.query(`
            CREATE TABLE IF NOT EXISTS active_alerts (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100),
                alert_type VARCHAR(255),
                severity VARCHAR(50),
                related_domain VARCHAR(255),
                mitre_technique_id VARCHAR(50),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
    console.log("Created active_alerts table.");

    // --- ARCHIVAL TABLES ---
    await pool.query(`
      CREATE TABLE IF NOT EXISTS system_logs_archive (
        LIKE system_logs INCLUDING DEFAULTS
      );
      CREATE INDEX IF NOT EXISTS idx_syslog_archive_ts ON system_logs_archive(timestamp DESC);
    `);
    console.log("Created system_logs_archive table.");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS network_logs_archive (
        LIKE network_logs INCLUDING DEFAULTS
      );
      CREATE INDEX IF NOT EXISTS idx_netlog_archive_ts ON network_logs_archive(timestamp DESC);
    `);
    console.log("Created network_logs_archive table.");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS activity_logs_archive (
        LIKE activity_logs INCLUDING DEFAULTS
      );
      CREATE INDEX IF NOT EXISTS idx_actlog_archive_ts ON activity_logs_archive(timestamp DESC);
    `);
    console.log("Created activity_logs_archive table.");

    await pool.query(`
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
    `);
    console.log("Created archive_runs table.");

  } catch (e) {
    console.error("Error:", e);
  } finally {
    pool.end();
  }
}
run();

