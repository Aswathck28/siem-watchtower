const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432,
});

async function runDebug() {
    try {
        console.log('--- USER DATA ---');
        const userRes = await pool.query("SELECT * FROM users WHERE email = '123456@gmail.com'");
        console.log(JSON.stringify(userRes.rows, null, 2));
        
        if (userRes.rows.length > 0) {
            const user = userRes.rows[0];
            const uid = user.firebase_uid;
            const hostname = user.hostname;
            
            console.log('\n--- RECENT SYSTEM LOGS ---');
            const logsRes = await pool.query("SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 10");
            console.log(JSON.stringify(logsRes.rows, null, 2));
            
            console.log('\n--- LOGS BY HOSTNAME ONLY ---');
            const hostLogsRes = await pool.query("SELECT count(*) FROM system_logs WHERE hostname = $1", [hostname]);
            console.log(`Count for ${hostname}:`, hostLogsRes.rows[0].count);
            
            console.log('\n--- LOGS BY UID IN DETAILS ---');
            const uidLogsRes = await pool.query("SELECT count(*) FROM system_logs WHERE details::jsonb->>'user_id' = $1", [uid]);
            console.log(`Count for UID ${uid}:`, uidLogsRes.rows[0].count);
            
            console.log('\n--- LOGS BY SYSTEM_AGENT IN DETAILS ---');
            const agentLogsRes = await pool.query("SELECT count(*) FROM system_logs WHERE details::jsonb->>'user_id' = 'SYSTEM_AGENT'");
            console.log(`Count for SYSTEM_AGENT:`, agentLogsRes.rows[0].count);
        }
        
        await pool.end();
    } catch (err) {
        console.error('Error:', err);
    }
}

runDebug();
