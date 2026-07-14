import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import './WebsiteThreatMonitor.css';

/**
 * Component: WebsiteThreatMonitor
 * Description: Dedicated analytical dashboard for web-based telemetry. 
 *              Visualizes top visited domains, HTTPS/HTTP ratios, and 
 *              recorded MITRE technique frequencies for inbound 
 *              website requests.
 * Parameters:
 *   - None (Uses internal useEffect polling/state management)
 * Returns:
 *   - JSX.Element
 */
const WebsiteThreatMonitor = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchData = async () => {
        try {
            const user = JSON.parse(localStorage.getItem('user'));
            const uid = user ? user.uid : '';
            const response = await fetch(`http://localhost:5000/api/reports/website-summary?requester_uid=${uid}`);
            if (response.ok) {
                const json = await response.json();
                setData(json);
            }
        } catch (error) {
            console.error("Failed to fetch website summary:", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 10000); // 10s auto-refresh
        return () => clearInterval(interval);
    }, []);

    if (loading || !data) {
        return <div style={{ color: '#0ff', padding: '2rem' }}>INITIALIZING THREAT MONITOR...</div>;
    }

    // Prepare Pie Chart Data
    const pieData = [
        { name: 'Secure (HTTPS)', value: data.secure_count },
        { name: 'Not Secure (HTTP)', value: data.insecure_count }
    ];
    const COLORS = ['#00FF88', '#FF3366'];

    // Severity Badge Helper
    const getBadgeStyle = (level) => {
        if (!level) return { background: '#333', color: '#fff' };
        if (level.toUpperCase() === 'HIGH') return { background: 'rgba(255,51,102,0.2)', color: '#FF3366', border: '1px solid #FF3366' };
        if (level.toUpperCase() === 'MEDIUM') return { background: 'rgba(255,170,0,0.2)', color: '#FFAA00', border: '1px solid #FFAA00' };
        if (level.toUpperCase() === 'LOW') return { background: 'rgba(0,255,136,0.2)', color: '#00FF88', border: '1px solid #00FF88' };
        return { background: '#222', color: '#aaa', border: '1px solid #aaa' };
    };

    return (
        <div className="threat-monitor-container">
            <h2 className="section-title">WEBSITE THREAT MONITORING</h2>

            {/* KPI Metrics row */}
            <div className="kpi-grid">
                <div className="kpi-card">
                    <div className="kpi-label">TOTAL VISITS</div>
                    <div className="kpi-value">{data.total_web_visits}</div>
                </div>
                <div className="kpi-card" style={{ borderColor: 'rgba(0,255,136,0.5)' }}>
                    <div className="kpi-label" style={{ color: '#00FF88' }}>SECURE (HTTPS)</div>
                    <div className="kpi-value">{data.secure_count}</div>
                </div>
                <div className="kpi-card" style={{ borderColor: 'rgba(255,51,102,0.5)' }}>
                    <div className="kpi-label" style={{ color: '#FF3366' }}>INSECURE (HTTP)</div>
                    <div className="kpi-value">{data.insecure_count}</div>
                </div>
                <div className="kpi-card" style={{ borderColor: 'rgba(255,170,0,0.5)' }}>
                    <div className="kpi-label" style={{ color: '#FFAA00' }}>HIGH RISK SITES</div>
                    <div className="kpi-value">{data.high_risk_count}</div>
                </div>
                <div className="kpi-card" style={{ borderColor: 'rgba(255,51,102,0.8)' }}>
                    <div className="kpi-label" style={{ color: '#FF3366', fontWeight: 700 }}>ACTIVE ALERTS</div>
                    <div className="kpi-value">{data.total_alerts}</div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="charts-grid">
                <div className="chart-box">
                    <h3 className="chart-title">TOP DOMAINS VISITED</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={data.top_5_domains} layout="vertical" margin={{ top: 5, right: 30, left: 60, bottom: 5 }}>
                            <XAxis type="number" stroke="#44b" />
                            <YAxis dataKey="domain" type="category" stroke="#0ff" width={100} tick={{ fontSize: 12, fill: '#0aF' }} />
                            <Tooltip cursor={{ fill: 'rgba(0,255,255,0.1)' }} contentStyle={{ backgroundColor: '#001', borderColor: '#0ff' }} />
                            <Bar dataKey="count" fill="#0ff" radius={[0, 4, 4, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
                <div className="chart-box">
                    <h3 className="chart-title">ENCRYPTION RATIO</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                            <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                                {pieData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#001', borderColor: '#0ff' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
                <div className="chart-box">
                    <h3 className="chart-title">TOP MITRE TECHNIQUES</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={data.top_mitre_techniques}>
                            <XAxis dataKey="mitre_technique_id" stroke="#44b" tick={{ fill: '#0aF' }} />
                            <YAxis stroke="#44b" />
                            <Tooltip cursor={{ fill: 'rgba(0,255,255,0.1)' }} contentStyle={{ backgroundColor: '#001', borderColor: '#0ff' }} />
                            <Bar dataKey="count" fill="#F36" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Active Alerts Table */}
            <div className="data-table-section">
                <h3 className="table-title" style={{ color: '#FF3366' }}>ACTIVE THREAT ALERTS</h3>
                <div className="table-wrapper">
                    <table className="threat-table">
                        <thead>
                            <tr>
                                <th>TIMESTAMP</th>
                                <th>USER</th>
                                <th>ALERT TYPE</th>
                                <th>SEVERITY</th>
                                <th>DOMAIN</th>
                                <th>MITRE ID</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.active_alerts.map((alert, idx) => (
                                <tr key={idx}>
                                    <td>{new Date(alert.timestamp).toLocaleString()}</td>
                                    <td>{alert.username}</td>
                                    <td style={{ color: '#FFF' }}>{alert.alert_type}</td>
                                    <td><span className="badge" style={getBadgeStyle(alert.severity)}>{alert.severity}</span></td>
                                    <td style={{ color: '#0ff' }}>{alert.related_domain}</td>
                                    <td><span className="mitre-badge">{alert.mitre_technique_id}</span></td>
                                </tr>
                            ))}
                            {data.active_alerts.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center', color: '#44b' }}>No Active Alerts</td></tr>}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Recent Activity Table */}
            <div className="data-table-section">
                <h3 className="table-title">RECENT WEBSITE ACTIVITY</h3>
                <div className="table-wrapper">
                    <table className="threat-table">
                        <thead>
                            <tr>
                                <th>TIMESTAMP</th>
                                <th>USER</th>
                                <th>DOMAIN</th>
                                <th>SECURITY STATUS</th>
                                <th>RISK LEVEL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.recent_logs.map((log, idx) => (
                                <tr key={idx}>
                                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                                    <td>{log.user}</td>
                                    <td style={{ color: '#0ff' }}>{log.domain}</td>
                                    <td>
                                        <span style={{ color: log.security_status?.includes('HTTPS') ? '#00FF88' : '#FF3366' }}>
                                            {log.security_status}
                                        </span>
                                    </td>
                                    <td><span className="badge" style={getBadgeStyle(log.risk_level)}>{log.risk_level || 'UNKNOWN'}</span></td>
                                </tr>
                            ))}
                            {data.recent_logs.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center', color: '#44b' }}>No recent web activity.</td></tr>}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    );
};

export default WebsiteThreatMonitor;
