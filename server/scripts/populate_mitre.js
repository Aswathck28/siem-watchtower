const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'siem-watchtower',
  password: 'pava4484',
  port: 5432,
});

async function populateMatrix() {
  try {
    console.log('Fetching MITRE techniques from mitre_definitions...');
    const result = await pool.query('SELECT matrix_id FROM mitre_definitions');
    const allTechniques = result.rows.map(row => row.matrix_id);
    
    if (allTechniques.length === 0) {
        console.error('No techniques found in mitre_definitions! Did you run seed_mitre.js?');
        process.exit(1);
    }

    // Shuffle the array to randomly select techniques
    for (let i = allTechniques.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [allTechniques[i], allTechniques[j]] = [allTechniques[j], allTechniques[i]];
    }

    const targetCount = Math.floor(allTechniques.length * 0.75); // 75% coverage
    const techniquesToColor = allTechniques.slice(0, targetCount);
    
    // Split into red (active threats) and green (historical)
    const redCount = Math.floor(targetCount * 0.4); // 40% of the 75% will be red
    const historicalCount = targetCount - redCount;

    console.log(`Total Techniques Found: ${allTechniques.length}`);
    console.log(`Targeting ${targetCount} techniques (75%).`);
    
    await pool.query('BEGIN');
    
    let injectedGreen = 0;
    let injectedRed = 0;

    for (let i = 0; i < techniquesToColor.length; i++) {
        const techId = techniquesToColor[i];
        
        if (i < historicalCount) {
             // GREEN: Historical Coverage (Regular system_logs entry)
             // Insert multiple times for volume? Just 1 is enough for the frontend to register it in data.mitre
             await pool.query(`
                 INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details)
                 VALUES (NOW() - (random() * interval '7 days'), 'DESKTOP-NJVO94I', 'SIMULATED_BASELINE', $1, '{"status": "Historical Detection", "action": "verified safe"}')
             `, [techId]);
             
             injectedGreen++;
        } else {
             // RED: Active Threat (event_type contains 'FAIL' to trigger sysThreatsRes in backend)
             await pool.query(`
                 INSERT INTO system_logs (timestamp, hostname, event_type, mapped_technique_id, details)
                 VALUES (NOW() - (random() * interval '2 hours'), 'DESKTOP-NJVO94I', 'SIMULATED_FAIL', $1, '{"status": "Active Threat", "action": "breach detected"}')
             `, [techId]);
             
             injectedRed++;
        }
    }
    
    await pool.query('COMMIT');
    console.log('SUCCESS! Matrix populated exactly as requested.');
    console.log(`- ${injectedGreen} techniques marked as Historical (Green).`);
    console.log(`- ${injectedRed} techniques marked as Active Threats (Red).`);
    
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Error populating matrix:', err);
  } finally {
    await pool.end();
  }
}

populateMatrix();
