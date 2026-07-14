const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { Pool } = require('pg');
require('dotenv').config();

// Re-use the existing pool config if possible, or create a new one
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
});

const ARCHIVE_DIR = path.join(__dirname, 'logs', 'archive');

// Ensure archive directory exists
if (!fs.existsSync(ARCHIVE_DIR)) {
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
}

/**
 * Function: archiveOldLogs
 * Description: Performs a maintenance operation that identifies database log entries older 
 *              than a specified threshold, exports them into a compressed GZIP JSON file, 
 *              and then purges the archived records from the live database tables.
 * Parameters:
 *   - daysToKeep (number): The retention period in days. Logs older than this will be archived. 
 *                          Defaults to 2.
 * Returns:
 *   - Promise<object>: An object containing the operation status, count of archived records, 
 *                      the resulting filename, and the file size in KB.
 */
async function archiveOldLogs(daysToKeep = 2) {
    if (daysToKeep < 0) daysToKeep = 0; // Safety

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
    const cutoffISO = cutoffDate.toISOString();

    console.log(`[ARCHIVER] Starting archive for logs older than ${cutoffISO}...`);

    try {
        // 1. SELECT Logs to Archive
        // We do this in a transaction to ensure consistency
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            // Fetch System Logs
            const sysRes = await client.query('SELECT * FROM system_logs WHERE timestamp < $1', [cutoffISO]);
            const sysLogs = sysRes.rows;

            // Fetch Activity Logs
            const actRes = await client.query('SELECT * FROM activity_logs WHERE timestamp < $1', [cutoffISO]);
            const actLogs = actRes.rows;

            const totalCount = sysLogs.length + actLogs.length;

            if (totalCount === 0) {
                console.log('[ARCHIVER] No logs to archive.');
                await client.query('ROLLBACK');
                return { status: 'success', archived: 0, message: 'No logs older than ' + daysToKeep + ' days.' };
            }

            console.log(`[ARCHIVER] Found ${totalCount} logs (${sysLogs.length} system, ${actLogs.length} activity). Compressing...`);

            // 2. Write to File (Compressed)
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `archive_${timestamp}.json.gz`;
            const filePath = path.join(ARCHIVE_DIR, filename);

            const archiveData = {
                meta: {
                    archivedAt: new Date().toISOString(),
                    cutoffDate: cutoffISO,
                    systemLogsCount: sysLogs.length,
                    activityLogsCount: actLogs.length
                },
                system_logs: sysLogs,
                activity_logs: actLogs
            };

            // GZIP Compression
            const jsonString = JSON.stringify(archiveData);
            const gzip = zlib.gzipSync(jsonString);

            fs.writeFileSync(filePath, gzip);
            console.log(`[ARCHIVER] Wrote ${filePath} (${(gzip.length / 1024).toFixed(2)} KB)`);

            // 3. DELETE from DB
            // Only strictly delete what we fetched.
            // In a high-volume system, we might delete by ID range, but timestamp is okay here for simplicity.
            if (sysLogs.length > 0) {
                await client.query('DELETE FROM system_logs WHERE timestamp < $1', [cutoffISO]);
            }
            if (actLogs.length > 0) {
                await client.query('DELETE FROM activity_logs WHERE timestamp < $1', [cutoffISO]);
            }

            await client.query('COMMIT');
            console.log('[ARCHIVER] Cleanup complete. Database committed.');

            return {
                status: 'success',
                archived: totalCount,
                file: filename,
                sizeKB: (gzip.length / 1024).toFixed(2)
            };

        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ARCHIVER] Failed:', err);
        return { status: 'error', error: err.message };
    }
}

module.exports = { archiveOldLogs };
