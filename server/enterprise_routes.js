/**
 * SIEM Watchtower — Enterprise Routes
 * Detection engine, threat scores, reports, MITRE analytics
 */

/**
 * Function: registerEnterpriseRoutes
 * Description: Registers all enterprise-level API endpoints for the SIEM application,
 *              including detection management, threat scoring, and system reporting.
 * Parameters:
 *   - app (Express Instance): The Express application instance.
 *   - pool (pg.Pool): The PostgreSQL connection pool for database queries.
 * Returns:
 *   - None: Directly modifies the Express app by adding routes.
 */
module.exports = function registerEnterpriseRoutes(app, pool, requireAdminRequester) {
    const ALLOWED_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ALL']);
    const parseBoundedInt = (value, fallback, min, max) => {
        const parsed = Number.parseInt(value, 10);
        if (Number.isNaN(parsed)) return fallback;
        return Math.min(max, Math.max(min, parsed));
    };

    // --- GET ALL DETECTION RULES ---
    /**
     * Endpoint: GET /api/detection-rules
     * Description: Retrieves all active detection rules from the database, ordered by severity and name.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: An array of detection rule objects.
     */
    app.get('/api/detection-rules', requireAdminRequester, async (req, res) => {
        try {
            const result = await pool.query('SELECT * FROM detection_rules WHERE is_active = TRUE ORDER BY severity, rule_name');
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- GET TRIGGERED DETECTIONS ---
    /**
     * Endpoint: GET /api/detections
     * Description: Fetches triggered security detections with support for filtering by severity, 
     *              acknowledgment status, and pagination.
     * Parameters:
     *   - req.query.severity (str): Filter by severity level (e.g., 'HIGH').
     *   - req.query.acknowledged (str): Filter by 'true' or 'false'.
     *   - req.query.limit (int): Number of records per page. Defaults to 200.
     *   - req.query.page (int): Page number for pagination. Defaults to 1.
     * Returns:
     *   - JSON: Object containing total count and the array of detections.
     */
    app.get('/api/detections', requireAdminRequester, async (req, res) => {
        const { severity, acknowledged } = req.query;
        const limit = parseBoundedInt(req.query.limit, 200, 1, 1000);
        const page = parseBoundedInt(req.query.page, 1, 1, 100000);
        const offset = (page - 1) * limit;
        let conditions = [];
        let params = [];
        let idx = 1;
        if (severity && severity !== 'ALL') {
            if (!ALLOWED_SEVERITIES.has(String(severity).toUpperCase())) {
                return res.status(400).json({ error: 'Invalid severity value' });
            }
            conditions.push(`severity = $${idx++}`);
            params.push(String(severity).toUpperCase());
        }
        if (acknowledged !== undefined && acknowledged !== 'all') { 
            if (acknowledged !== 'true' && acknowledged !== 'false') {
                return res.status(400).json({ error: 'acknowledged must be true, false, or all' });
            }
            conditions.push(`acknowledged = $${idx++}`); 
            params.push(acknowledged === 'true'); 
        }
        const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
        try {
            const totalRes = await pool.query(`SELECT COUNT(*) FROM triggered_detections ${where}`, params);
            const result = await pool.query(
                `SELECT * FROM triggered_detections ${where} ORDER BY timestamp DESC LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]
            );
            res.json({ total: parseInt(totalRes.rows[0].count), detections: result.rows });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- DETECTION STATS ---
    /**
     * Endpoint: GET /api/detections/stats
     * Description: Provides aggregated statistics about detections, including counts by 
     *              severity, recent activity (24h), and unacknowledged alerts.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: Object containing statistics for dashboard visualization.
     */
    app.get('/api/detections/stats', requireAdminRequester, async (req, res) => {
        try {
            const [bySev, recent, unacked] = await Promise.all([
                pool.query(`SELECT severity, COUNT(*) as count FROM triggered_detections GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END`),
                pool.query(`SELECT COUNT(*) as count FROM triggered_detections WHERE timestamp > NOW() - INTERVAL '24 hours'`),
                pool.query(`SELECT COUNT(*) as count FROM triggered_detections WHERE acknowledged = FALSE`)
            ]);
            res.json({ by_severity: bySev.rows, last_24h: parseInt(recent.rows[0].count), unacknowledged: parseInt(unacked.rows[0].count) });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- ACKNOWLEDGE A DETECTION ---
    /**
     * Endpoint: PATCH /api/detections/:id/acknowledge
     * Description: Marks a specific triggered detection as acknowledged by an administrator.
     * Parameters:
     *   - req.params.id (int): Unique ID of the detection.
     *   - req.body.acknowledged_by (str): The username/role of the acknowledger. Defaults to 'ADMIN'.
     * Returns:
     *   - JSON: Success status object.
     */
    app.patch('/api/detections/:id/acknowledge', requireAdminRequester, async (req, res) => {
        const { id } = req.params;
        const { acknowledged_by = 'ADMIN' } = req.body;
        const detectionId = Number.parseInt(id, 10);
        if (!Number.isInteger(detectionId) || detectionId <= 0) {
            return res.status(400).json({ error: 'Invalid detection id' });
        }
        if (typeof acknowledged_by !== 'string' || !acknowledged_by.trim() || acknowledged_by.length > 255) {
            return res.status(400).json({ error: 'Invalid acknowledged_by value' });
        }
        try {
            const updateRes = await pool.query(
                `UPDATE triggered_detections SET acknowledged = TRUE, acknowledged_by = $1, acknowledged_at = NOW() WHERE id = $2`,
                [acknowledged_by.trim(), detectionId]
            );
            if (updateRes.rowCount === 0) {
                return res.status(404).json({ error: 'Detection not found' });
            }
            res.json({ status: 'acknowledged' });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- BULK ACKNOWLEDGE ---
    /**
     * Endpoint: PATCH /api/detections/acknowledge-all
     * Description: Acknowledges all outstanding detections, optionally filtered by a specific severity level.
     * Parameters:
     *   - req.body.severity (str): Optional severity level to filter the bulk action.
     * Returns:
     *   - JSON: Count of records updated.
     */
    app.patch('/api/detections/acknowledge-all', requireAdminRequester, async (req, res) => {
        const { severity } = req.body;
        let query = `UPDATE triggered_detections SET acknowledged = TRUE, acknowledged_at = NOW() WHERE acknowledged = FALSE`;
        const params = [];
        if (severity && severity !== 'ALL') {
            const normalizedSeverity = String(severity).toUpperCase();
            if (!ALLOWED_SEVERITIES.has(normalizedSeverity)) {
                return res.status(400).json({ error: 'Invalid severity value' });
            }
            query += ` AND severity = $1`;
            params.push(normalizedSeverity);
        }
        try {
            const r = await pool.query(query, params);
            res.json({ acknowledged: r.rowCount });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- THREAT SCORES ---
    /**
     * Endpoint: GET /api/threat-scores
     * Description: Retrieves the top 20 entities (hosts or users) with the highest cumulative risk scores.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: Array of threat score objects.
     */
    app.get('/api/threat-scores', requireAdminRequester, async (req, res) => {
        try {
            const result = await pool.query('SELECT * FROM threat_scores ORDER BY score DESC LIMIT 20');
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- SUSPICIOUS IPs ---
    /**
     * Endpoint: GET /api/suspicious-ips
     * Description: Fetches up to 50 identified malicious IP addresses, ranked by their threat score.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: Array of suspicious IP objects.
     */
    app.get('/api/suspicious-ips', requireAdminRequester, async (req, res) => {
        try {
            // Rank by threat_score as requested
            const result = await pool.query('SELECT * FROM suspicious_ips ORDER BY threat_score DESC, last_seen DESC LIMIT 50');
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- DEVICE HISTORY ---
    /**
     * Endpoint: GET /api/device-history
     * Description: Retrieves device connectivity and identification history for a specific Firebase User UID.
     * Parameters:
     *   - req.query.uid (str): The unique Firebase ID of the user.
     * Returns:
     *   - JSON: Array of historical device connection records.
     */
    app.get('/api/device-history', requireAdminRequester, async (req, res) => {
        const { uid } = req.query;
        if (!uid) return res.status(400).json({ error: 'uid required' });
        try {
            const result = await pool.query('SELECT * FROM device_history WHERE user_id = $1 ORDER BY last_seen DESC', [uid]);
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- REPORT: THREAT SUMMARY ---
    /**
     * Endpoint: GET /api/reports/threat-summary
     * Description: Generates a high-level executive report summarizing detections, top hosts, 
     *              active alerts, and high-risk entities over a specified period.
     * Parameters:
     *   - req.query.days (int): Reporting window in days. Defaults to 7.
     * Returns:
     *   - JSON: Composite report object with multiple analytical segments.
     */
    app.get('/api/reports/threat-summary', requireAdminRequester, async (req, res) => {
        const days = parseBoundedInt(req.query.days, 7, 1, 90);
        try {
            const [detections, topRules, topHosts, alerts, topRisk] = await Promise.all([
                pool.query(`SELECT severity, COUNT(*) as count FROM triggered_detections WHERE timestamp > NOW() - ($1::int * INTERVAL '1 day') GROUP BY severity`, [days]),
                pool.query(`SELECT rule_name, mitre_id, severity, COUNT(*) as count FROM triggered_detections WHERE timestamp > NOW() - ($1::int * INTERVAL '1 day') GROUP BY rule_name, mitre_id, severity ORDER BY count DESC LIMIT 10`, [days]),
                pool.query(`SELECT hostname, COUNT(*) as detections, MAX(timestamp) as last_seen FROM triggered_detections WHERE timestamp > NOW() - ($1::int * INTERVAL '1 day') GROUP BY hostname ORDER BY detections DESC LIMIT 10`, [days]),
                pool.query(`SELECT severity, COUNT(*) as count FROM active_alerts WHERE timestamp > NOW() - ($1::int * INTERVAL '1 day') GROUP BY severity`, [days]),
                pool.query(`SELECT entity_id, entity_type, score, risk_level FROM threat_scores ORDER BY score DESC LIMIT 10`)
            ]);
            res.json({
                period_days: days,
                generated_at: new Date().toISOString(),
                severity_summary: detections.rows,
                top_triggered_rules: topRules.rows,
                top_affected_hosts: topHosts.rows,
                alert_summary: alerts.rows,
                top_risk_entities: topRisk.rows
            });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- REPORT: USER ACTIVITY ---
    /**
     * Endpoint: GET /api/reports/user-activity
     * Description: Retrieves the 500 most recent user-driven activity logs, merging 
     *              user email context for administrative transparency.
     * Parameters:
     *   - req.query.days (int): Monitoring window in days. Defaults to 7.
     * Returns:
     *   - JSON: Array of activity log objects.
     */
    app.get('/api/reports/user-activity', requireAdminRequester, async (req, res) => {
        const days = parseBoundedInt(req.query.days, 7, 1, 90);
        try {
            const result = await pool.query(`
                SELECT u.email, a.action_type, a.timestamp, a.source_ip, a.mapped_technique_id
                FROM activity_logs a
                LEFT JOIN users u ON a.user_id = u.firebase_uid
                WHERE a.timestamp > NOW() - ($1::int * INTERVAL '1 day')
                ORDER BY a.timestamp DESC LIMIT 500
            `, [days]);
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- REPORT: MITRE COVERAGE ---
    /**
     * Endpoint: GET /api/reports/mitre-coverage
     * Description: Analyzes the database for recorded detections and maps them against 
     *              the full MITRE ATT&CK framework to identify security coverage levels.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: Array of MITRE techniques with their current detection status.
     */
    app.get('/api/reports/mitre-coverage', requireAdminRequester, async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT d.matrix_id, d.name as technique_name, d.tactic,
                    COALESCE(cnt.count, 0) as detections,
                    CASE WHEN COALESCE(cnt.count, 0) > 10 THEN 'DETECTED'
                         WHEN COALESCE(cnt.count, 0) > 0  THEN 'PARTIALLY_DETECTED'
                         ELSE 'NOT_COVERED' END as coverage_status
                FROM mitre_definitions d
                LEFT JOIN (SELECT mapped_technique_id, COUNT(*) as count FROM system_logs GROUP BY mapped_technique_id) cnt
                    ON d.matrix_id = cnt.mapped_technique_id
                ORDER BY d.tactic, d.matrix_id
            `);
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- REPORT: ALERTS ---
    /**
     * Endpoint: GET /api/reports/alerts
     * Description: Retrieves a stream of recent system-generated alerts for audit purposes.
     * Parameters:
     *   - req.query.days (int): Selection window in days. Defaults to 7.
     * Returns:
     *   - JSON: Array of active alerts.
     */
    app.get('/api/reports/alerts', requireAdminRequester, async (req, res) => {
        const days = parseBoundedInt(req.query.days, 7, 1, 90);
        try {
            const result = await pool.query(
                `SELECT * FROM active_alerts WHERE timestamp > NOW() - ($1::int * INTERVAL '1 day') ORDER BY timestamp DESC LIMIT 500`,
                [days]
            );
            res.json(result.rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- MITRE TACTIC ANALYTICS ---
    /**
     * Endpoint: GET /api/mitre/analytics
     * Description: Provides deep-dive analytics into MITRE tactic frequencies, technique 
     *              confidence scores, and identified defensive gaps over a 30-day period.
     * Parameters:
     *   - req.query: None
     * Returns:
     *   - JSON: Object with tactics distribution, confidence metrics, and top weak spots.
     */
    app.get('/api/mitre/analytics', requireAdminRequester, async (req, res) => {
        try {
            const [tacticCounts, confidenceData, gapData] = await Promise.all([
                pool.query(`
                    SELECT COALESCE(d.tactic, 'Unknown') as tactic, COALESCE(COUNT(s.id), 0) as event_count
                    FROM mitre_definitions d
                    LEFT JOIN system_logs s ON s.mapped_technique_id = d.matrix_id AND s.timestamp > NOW() - INTERVAL '30 days'
                    GROUP BY d.tactic ORDER BY event_count DESC
                `),
                pool.query(`
                    SELECT d.matrix_id, d.name, d.tactic,
                        COALESCE(r.confidence_score, 50) as confidence_score,
                        COALESCE(cnt.count, 0) as detection_count,
                        CASE WHEN COALESCE(cnt.count, 0) > 10 THEN 'DETECTED'
                             WHEN COALESCE(cnt.count, 0) > 0  THEN 'PARTIAL'
                             ELSE 'GAP' END as status
                    FROM mitre_definitions d
                    LEFT JOIN detection_rules r ON d.matrix_id = r.mitre_id
                    LEFT JOIN (SELECT mapped_technique_id, COUNT(*) as count FROM system_logs GROUP BY mapped_technique_id) cnt ON d.matrix_id = cnt.mapped_technique_id
                    ORDER BY d.tactic
                `),
                pool.query(`
                    SELECT d.tactic, COUNT(*) as gap_count
                    FROM mitre_definitions d
                    LEFT JOIN system_logs s ON s.mapped_technique_id = d.matrix_id
                    WHERE s.id IS NULL
                    GROUP BY d.tactic ORDER BY gap_count DESC LIMIT 5
                `)
            ]);
            res.json({ tactic_counts: tacticCounts.rows, technique_confidence: confidenceData.rows, weak_spots: gapData.rows });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- THREAT SCORE UPDATE UTILITY (exported for inline use) ---
    /**
     * Function: app.updateThreatScore
     * Description: A system-wide utility to dynamically update the threat score for a host or user based 
     *              on the severity of detected events. Recalculates risk levels (LOW to CRITICAL).
     * Parameters:
     *   - entityId (str): Unique identifier for the entity (e.g., hostname).
     *   - severity (str): Severity of the trigger event ('CRITICAL', 'HIGH', etc.).
     *   - reason (str): Human-readable reason for the score increment.
     *   - entityType (str): Type of entity, defaults to 'HOST'.
     * Returns:
     *   - None: Updates the database asynchronously.
     */
    app.updateThreatScore = async (entityId, severity, reason, entityType = 'HOST') => {
        const scoreMap = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 };
        const increment = scoreMap[severity] || 5;
        try {
            await pool.query(`
                INSERT INTO threat_scores (entity_id, entity_type, score, risk_level, factors, last_updated)
                VALUES ($1, $2, $3, 'LOW', $4, NOW())
                ON CONFLICT (entity_id) DO UPDATE SET
                    entity_type = EXCLUDED.entity_type,
                    score = LEAST(100.0, threat_scores.score + EXCLUDED.score),
                    risk_level = CASE
                        WHEN LEAST(100.0, threat_scores.score + EXCLUDED.score) >= 75 THEN 'CRITICAL'
                        WHEN LEAST(100.0, threat_scores.score + EXCLUDED.score) >= 50 THEN 'HIGH'
                        WHEN LEAST(100.0, threat_scores.score + EXCLUDED.score) >= 25 THEN 'MEDIUM'
                        ELSE 'LOW' END,
                    factors = (threat_scores.factors || EXCLUDED.factors::jsonb),
                    last_updated = NOW()
            `, [entityId, entityType, increment, JSON.stringify([{ reason, severity, ts: new Date().toISOString() }])]);
        } catch (e) { console.error('[THREAT SCORE]', e.message); }
    };
};
