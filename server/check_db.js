
const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432,
});

async function checkDb() {
    try {
        const res = await pool.query('SELECT current_database(), current_user');
        console.log('Connected to:', res.rows[0]);
        const tables = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
        console.log('Tables:', tables.rows.map(r => r.table_name));
        process.exit(0);
    } catch (err) {
        console.error('Database connection error:', err.message);
        process.exit(1);
    }
}

checkDb();
