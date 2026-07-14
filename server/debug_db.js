const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432
});

async function check() {
    try {
        const res = await pool.query(`
            SELECT hostname, event_type, details::jsonb->>'user_action' as action, details::jsonb->>'user_id' as uid, timestamp 
            FROM system_logs 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            ORDER BY timestamp DESC 
            LIMIT 20
        `);
        console.log('LATEST LOGS:', JSON.stringify(res.rows, null, 2));

        const users = await pool.query('SELECT firebase_uid, email, hostname FROM users');
        console.log('USERS:', JSON.stringify(users.rows, null, 2));

    } catch (err) {
        console.error(err);
    } finally {
        await pool.end();
    }
}

check();