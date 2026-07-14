//server/seed_mitre.js:
// File: server/seed_mitre.js
const { Pool } = require('pg');
const axios = require('axios');
require('dotenv').config();

// 1. Setup Database Connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: process.env.DB_PASS || 'pava4484',
    port: 5432,
});

// 2. The URL for the official MITRE Framework Data
const MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

// Data ingestion mechanism pulling the live global enterprise attack graph payload merging descriptions and kill-chains directly into the relational intelligence repository
/**
 * Function: seedDatabase
 * Description: Orchestrates the synchronization of the local SIEM 
 *              intelligence repository with the official MITRE ATT&CK 
 *              framework. Downloads 700+ techniques, filters for 
 *              active patterns, and performs an 'upsert' to ensure 
 *              descriptions and tactics remain current.
 * Parameters:
 *   - None
 * Returns:
 *   - Promise: Resolves upon successful database population.
 */
const seedDatabase = async () => {
    try {
        console.log('🔵 Connecting to Database...');

        // Download the data from MITRE
        console.log('🔵 Downloading MITRE Framework (700+ Items)...');
        const { data } = await axios.get(MITRE_JSON_URL);
        const attacks = data.objects.filter(obj => obj.type === 'attack-pattern' && !obj.deprecated);

        console.log(`🟢 Found ${attacks.length} active attack techniques.`);

        // Insert each technique into the DB
        let count = 0;
        for (const item of attacks) {
            // Find the ID (e.g., T1059)
            const mitreId = item.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;

            // Find the Tactic (e.g., Execution)
            const tactic = item.kill_chain_phases?.map(p => p.phase_name).join(', ') || 'Unknown';

            if (mitreId) {
                await pool.query(
                    `INSERT INTO mitre_definitions (matrix_id, name, description, tactic, url)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (matrix_id) DO UPDATE 
                     SET tactic = EXCLUDED.tactic,
                         name = EXCLUDED.name,
                         description = EXCLUDED.description`, // Fix broken data
                    [mitreId, item.name, item.description, tactic, 'https://attack.mitre.org']
                );
                count++;
            }
        }

        console.log(`✅ SUCCESS: Uploaded ${count} definitions to the database.`);
        process.exit(0);

    } catch (err) {
        console.error('🔴 Error:', err.message);
        process.exit(1);
    }
};

seedDatabase();