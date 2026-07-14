const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432
});

async function checkLockLogs() {
    try {
        const result = await pool.query(
            `SELECT timestamp, event_type, details, hostname FROM system_logs 
             WHERE event_type = 'Authentication' 
             ORDER BY timestamp DESC LIMIT 10`
        );
        console.log('Authentication Logs (Lock/Unlock/Login/Logout):');
        console.log('===============================================');
        result.rows.forEach(row => {
            const details = typeof row.details === 'string' ? JSON.parse(row.details) : row.details;
            const action = details.action || details.user_action || 'N/A';
            console.log(`${row.timestamp}: ${action} (${row.hostname || 'N/A'})`);
        });
        if (result.rows.length === 0) {
            console.log('No lock/unlock logs found in database.');
        }
        
        // Check latest timestamp
        const latestResult = await pool.query(
            `SELECT MAX(timestamp) as latest FROM system_logs WHERE event_type = 'Authentication'`
        );
        console.log('\nLatest Authentication log:', latestResult.rows[0].latest || 'None');
        
        // Check active hostnames
        console.log('\nNote: Lock/unlock events are only collected when a user is logged into the SIEM dashboard.');
        console.log('Your hostname: DESKTOP-NJVO94I');
        console.log('To collect lock/unlock logs:');
        console.log('  1. Log in to SIEM dashboard');
        console.log('  2. Lock your computer (Win+L)');
        console.log('  3. Unlock your computer');
        console.log('  4. Check the dashboard - events will appear');
    } catch (e) {
        console.error('Error:', e.message);
    } finally {
        await pool.end();
    }
}

checkLockLogs();
