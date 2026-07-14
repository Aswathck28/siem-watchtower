
const { Pool } = require('pg');
const fs = require('fs');

// I'll use a Python script for Pillow as it's already working and I have the dependencies.
// But I need to pass the DB data to it.

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432,
});

async function getDbStats() {
    try {
        const tables = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
        const stats = [];
        for (const row of tables.rows) {
            const countRes = await pool.query(`SELECT COUNT(*) FROM ${row.table_name}`);
            stats.push({ name: row.table_name, count: countRes.rows[0].count });
        }
        console.log(JSON.stringify(stats));
        process.exit(0);
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
}

getDbStats();
