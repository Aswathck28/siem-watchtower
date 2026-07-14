const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432
});

async function checkBattery() {
    try {
        const result = await pool.query(
            `SELECT timestamp, event_type, details FROM system_logs 
             WHERE event_type IN ('BATTERY_STATUS', 'CHARGER_PLUGGED_IN', 'CHARGER_UNPLUGGED', 'BATTERY_CRITICAL') 
             ORDER BY timestamp DESC LIMIT 10`
        );
        console.log('Recent Battery Logs:');
        console.log('=====================');
        result.rows.forEach(row => {
            const details = typeof row.details === 'string' ? JSON.parse(row.details) : row.details;
            const level = details.level || details.percent || details.batteryPercent || 'N/A';
            console.log(`${row.timestamp}: ${row.event_type} - Level: ${level}%`);
        });
        
        if (result.rows.length === 0) {
            console.log('No battery logs found in database.');
        }
    } catch (e) {
        console.error('Error:', e.message);
    } finally {
        await pool.end();
    }
}

checkBattery();
