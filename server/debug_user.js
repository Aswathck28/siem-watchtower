const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432,
});

async function checkUser() {
    try {
        const users = await pool.query("SELECT firebase_uid, email, hostname, session_start_time FROM users WHERE email = '123456@gmail.com'");
        console.log('User:', JSON.stringify(users.rows, null, 2));
        
        if (users.rows.length > 0) {
            const hostname = users.rows[0].hostname;
            const logs = await pool.query("SELECT * FROM system_logs WHERE hostname = $1 ORDER BY timestamp DESC LIMIT 5", [hostname]);
            console.log(`Logs for ${hostname}:`, JSON.stringify(logs.rows, null, 2));
        }
        
        process.exit(0);
    } catch (err) {
        console.error('Error:', err.message);
        process.exit(1);
    }
}

checkUser();
