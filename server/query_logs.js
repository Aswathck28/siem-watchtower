/**
 * Utility: query_logs.js
 * Description: Lightweight forensic diagnostics tool that executes 
 *              direct SQL queries against the system_logs table. 
 *              Used for rapid verification of raw telemetry ingestion.
 */
const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgres://postgres:pava4484@localhost:5432/siem-watchtower' });
pool.query("SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 20").then(r => { console.log(JSON.stringify(r.rows, null, 2)); process.exit(0); }).catch(console.error);
