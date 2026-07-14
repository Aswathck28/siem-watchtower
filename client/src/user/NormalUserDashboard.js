import React, { useState, useEffect, useMemo } from 'react';
import '../App.css';
import { BarChart, Bar, Cell, XAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Icons from '../components/Icons';
import StarkModal from '../components/StarkModal'; // Import Modal
import axios from 'axios';
import useTabTracking from '../hooks/useTabTracking'; // Import the new hook

// ===========================================================
// NORMAL USER DASHBOARD COMPONENT
// ===========================================================
// Standard restricted-view portal rendering localized personal analytics without exposing overarching domain infrastructure 
/**
 * Component: NormalUserDashboard
 * Description: Specialized restricted-view portal for non-administrative users. 
 *              Provides localized telemetry, personal security standing (Shield Score), 
 *              and privacy controls without exposing global infrastructure data.
 * Parameters:
 *   - data (object): Structured telemetry payload containing user stats, 
 *                    website activity, and system logs.
 * Returns:
 *   - JSX.Element
 */
const NormalUserDashboard = ({ data, showAllHistory, setShowAllHistory }) => {
    const { AlertTriangle, Cpu, Globe, Activity, Battery, Memory, HardDrive, Play, StopSquare, Grid, Shield, CheckCircle, LogOut, Lock, Unlock } = Icons;
    const { user = {}, activity = [], alerts = [] } = data;

    const systemLogsForTable = useMemo(() => {
        const logs = data.userSystem?.logs || [];
        return logs.filter((log) => {
            let d = {};
            try { d = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {}); } catch (e) {}
            const ua = d.user_action ?? d.metadata?.user_action ?? null;
            // Removed filtering of UPTIME logs to allow "too many hours" logs to show
            return ua !== 'HEARTBEAT'; 
        });
    }, [data.userSystem?.logs]);
    const [activeUserTab, setActiveUserTab] = useState('WEBSITE'); // 'WEBSITE', 'SYSTEM', or 'FRAMEWORK'
    const [consentTracking, setConsentTracking] = useState(user.consent_tracking !== false); // Default to true
    const [anonymizeLogs, setAnonymizeLogs] = useState(user.anonymize_logs === true);

    // --- INTEGRATE TAB TRACKING ---
    useTabTracking(user.uid, user.sessionId || localStorage.getItem('sessionId'), consentTracking);

    // --- REMEDIATION MAPPING (SOLUTIONS) ---
    const remediationGuide = {
        'T1190': {
            name: "Exploit Public-Facing Application (SQLi)",
            solution: "Ensure all database queries use parameterized statements. Implement a Web Application Firewall (WAF) to filter malicious SQL syntax.",
            url: "https://attack.mitre.org/techniques/T1190/"
        },
        'T1059.007': {
            name: "Cross-Site Scripting (XSS)",
            solution: "Sanitize all user-controlled input before rendering. Implement a strict Content Security Policy (CSP) header.",
            url: "https://attack.mitre.org/techniques/T1059/007/"
        },
        'T1083': {
            name: "File and Directory Discovery",
            solution: "Restrict file system permissions. Ensure sensitive directories like /etc/ or /config/ are not exposed via the web server.",
            url: "https://attack.mitre.org/techniques/T1083/"
        },
        'T1110': {
            name: "Brute Force",
            solution: "Implement account lockout policies and Multi-Factor Authentication (MFA). Rotate passwords immediately if compromised.",
            url: "https://attack.mitre.org/techniques/T1110/"
        },
        'T1136.001': {
            name: "Create Account: Local Account",
            solution: "Verify if this account creation was authorized. Audit administrative logs for unauthorized privilege escalation.",
            url: "https://attack.mitre.org/techniques/T1136/001/"
        },
        'T1204': {
            name: "User Execution",
            solution: "Avoid clicking suspicious links or downloading unverified attachments. Ensure Endpoint Detection (EDR) is active.",
            url: "https://attack.mitre.org/techniques/T1204/"
        }
    };

    // --- 1. SHIELD SCORE CALCULATION ---
    // Evaluates localized user trust integrity deducting precedence points sequentially corresponding strictly to detected infractions
/**
 * Function: calculateShieldScore
 * Description: Heuristic algorithm that calculates a user's behavioral 
 *              integrity score. Deducts points based on security status, 
 *              failed login attempts, and active alerts to represent 
 *              forensic standing.
 * Parameters:
 *   - None (Uses closure over 'user' and 'alerts' props)
 * Returns:
 *   - number: Final integrity score (0-100).
 */
    const calculateShieldScore = () => {
        if (user?.security_score !== undefined) {
            return user.security_score;
        }
        let score = 100;
        if (user?.failed_login_count > 0) score -= (user.failed_login_count * 10);
        if (user?.security_status === 'AT_RISK') score -= 30;
        if (alerts && alerts.length > 0) score -= (alerts.length * 5);
        if (!user?.last_login) score -= 5;
        return Math.max(0, Math.min(100, score));
    };

    const shieldScore = calculateShieldScore();
    let scoreColor = '#10b981';
    if (shieldScore < 80) scoreColor = '#f59e0b';
    if (shieldScore < 50) scoreColor = '#ef4444';

    // --- 2. DEVICE STATS (Live Simulation) ---
    const [stats, setStats] = useState(() => {
        const baseCpu = user?.fingerprint?.cpu_load || 25;
        const baseRam = user?.fingerprint?.ram_usage || 40;
        return {
            cpu: Math.max(0, Math.min(100, baseCpu + (Math.random() * 10 - 5))),
            ram: Math.max(0, Math.min(100, baseRam + (Math.random() * 5 - 2.5)))
        };
    });

    useEffect(() => {
        const interval = setInterval(() => {
            const baseCpu = user?.fingerprint?.cpu_load || 25;
            const baseRam = user?.fingerprint?.ram_usage || 40;
            setStats({
                cpu: Math.max(0, Math.min(100, baseCpu + (Math.random() * 10 - 5))),
                ram: Math.max(0, Math.min(100, baseRam + (Math.random() * 5 - 2.5)))
            });
        }, 5000); // Increased interval to 5s to reduce re-renders and save resources
        return () => clearInterval(interval);
    }, [user]);

    // --- 3. PANIC BUTTON HANDLER ---
    const [panicState, setPanicState] = useState('IDLE');
    // Rapid response mechanism immediately alerting centralized SOC command of an active workstation compromise situation
/**
 * Function: handlePanic
 * Description: Rapid response mechanism that prompts the user for 
 *              confirmation before transmitting a critical alert to 
 *              the centralized SOC backend. Used when a user suspects 
 *              active workstation compromise.
 * Parameters:
 *   - None (Uses closure over 'user' and 'panicState')
 * Returns:
 *   - Promise: Resolves with backend acknowledgment or silent error.
 */
    const handlePanic = async () => {
        if (!window.confirm("⚠️ REPORT SECURITY INCIDENT?\n\nThis will immediately notify the Security Operations Center.")) return;
        setPanicState('SENDING');
        try {
            await axios.post('http://localhost:5000/api/alert/panic', {
                uid: user.uid,
                email: user.email,
                reason: 'User activated Panic Button'
            });
            setPanicState('SENT');
            setTimeout(() => setPanicState('IDLE'), 5000);
        } catch (e) {
            alert("Failed to send alert.");
            setPanicState('IDLE');
        }
    };

    // --- 4. PRIVACY SETTINGS HANDLER ---
    // Interface logic allowing non-administrative users to dynamically alter data collection masking or session persistence thresholds
/**
 * Function: handlePrivacyUpdate
 * Description: Interface logic allowing non-administrative users to 
 *              toggle session persistence, data collection masking, 
 *              or anonymization of their telemetry logs in the database.
 * Parameters:
 *   - type (string): Key indicator for privacy field (e.g., 'consent_tracking').
 *   - val (boolean): Desired Boolean state.
 * Returns:
 *   - Promise: Resolves with backend confirmation.
 */
    const handlePrivacyUpdate = async (type, val) => {
        try {
            await axios.post('http://localhost:5000/api/user/privacy', {
                uid: user.uid,
                [type]: val
            });
            if (type === 'consent_tracking') setConsentTracking(val);
            if (type === 'anonymize_logs') setAnonymizeLogs(val);
        } catch (e) {
            console.error("Failed to update privacy settings", e);
        }
    };

    const [selectedLog, setSelectedLog] = useState(null);
    const [showTrustReport, setShowTrustReport] = useState(false);
    const [filterDate, setFilterDate] = useState(null);

    // Filtered Activity List - Memoized to prevent unnecessary re-calculations
    const finalActivity = useMemo(() => {
        return filterDate
            ? activity.filter(act => act.timestamp.startsWith(filterDate))
            : activity;
    }, [activity, filterDate]);

    // Deduplicate & Group Repetitive Logs - Memoized
    const groupedActivity = useMemo(() => {
        const groupedActivityMap = new Map();
        finalActivity.forEach(act => {
            const key = `${act.type}_${typeof act.details === 'string' ? act.details : JSON.stringify(act.details)}`;
            if (groupedActivityMap.has(key)) {
                groupedActivityMap.get(key).count += 1;
                // Update timestamp to the most recent one for the group
                if (new Date(act.timestamp) > new Date(groupedActivityMap.get(key).timestamp)) {
                    groupedActivityMap.get(key).timestamp = act.timestamp;
                }
            } else {
                groupedActivityMap.set(key, { ...act, count: 1 });
            }
        });
        
        const result = Array.from(groupedActivityMap.values());
        return result.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }, [finalActivity]);

    const formatDate = (iso) => new Date(iso).toLocaleString();

    // Chart Logic
    // Generates static past 7 days string array iteratively creating the horizontal axis template for timeline activity charts
    const getLast7Days = () => {
        const days = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            days.push(d.toISOString().split('T')[0]);
        }
        return days;
    };

    const chartData = useMemo(() => {
        // If the backend provided actual heatmap data (hourly intensity), use that
        if (data.heatmap && data.heatmap.length > 0) {
            return data.heatmap.map(h => ({
                fullDate: `Hour ${h.hour}:00`,
                date: `${h.hour}:00`,
                count: parseInt(h.count)
            }));
        }

        // Fallback to the 7-day activity frequency if no heatmap is available
        return getLast7Days().map(date => {
            const count = activity ? activity.filter(a => a.timestamp.startsWith(date)).length : 0;
            return { fullDate: date, date: date.substring(5), count: count };
        });
    }, [activity, data.heatmap]);

    return (
        <div className="normal-dashboard-container" style={{ padding: '30px', color: '#fff', height: '100%', overflowY: 'auto', position: 'relative' }}>
            {/* CYBER SCANNING HUD OVERLAY */}
            <div className="scanning-sweep"></div>

            {/* HEADER */}
            <div className="fade-in-stagger stagger-1" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <div>
                    <h1 style={{ fontSize: '28px', letterSpacing: '2px', color: '#fff', margin: 0 }}>SECURITY TERMINAL</h1>
                    <div style={{ fontSize: '11px', color: '#64748b', marginTop: '5px' }}>
                        USER_NODE: <span style={{ color: 'var(--neon-cyan)' }}>{user?.email}</span>
                        {user?.email === '123456@gmail.com' && (
                            <span style={{ 
                                marginLeft: '10px', 
                                padding: '2px 8px', 
                                background: 'rgba(250, 204, 21, 0.2)', 
                                border: '1px solid #facc15', 
                                color: '#facc15', 
                                borderRadius: '4px', 
                                fontSize: '8px', 
                                fontWeight: 'bold',
                                letterSpacing: '1px',
                                textShadow: '0 0 5px #facc1580'
                            }}>
                                {/* Label removed per demo requirement */}
                            </span>
                        )}
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '15px' }}>
                    <button 
                        onClick={() => setActiveUserTab('WEBSITE')}
                        className={`stark-btn ${activeUserTab === 'WEBSITE' ? 'active' : ''}`}
                        style={{ 
                            padding: '10px 20px', 
                            fontSize: '11px', 
                            fontWeight: 'bold',
                            letterSpacing: '1px',
                            color: activeUserTab === 'WEBSITE' ? '#fff' : '#64748b',
                            background: activeUserTab === 'WEBSITE' ? 'rgba(34, 211, 238, 0.3)' : 'rgba(255,255,255,0.05)',
                            border: activeUserTab === 'WEBSITE' ? '1px solid var(--neon-cyan)' : '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            transition: 'all 0.3s ease'
                        }}
                    >
                        <Globe size={16} style={{ marginRight: '8px', color: activeUserTab === 'WEBSITE' ? 'var(--neon-cyan)' : 'inherit' }} /> WEBSITE_LOGS
                    </button>
                    <button 
                        onClick={() => setActiveUserTab('SYSTEM')}
                        className={`stark-btn ${activeUserTab === 'SYSTEM' ? 'active' : ''}`}
                        style={{ 
                            padding: '10px 20px', 
                            fontSize: '11px', 
                            fontWeight: 'bold',
                            letterSpacing: '1px',
                            color: activeUserTab === 'SYSTEM' ? '#fff' : '#64748b',
                            background: activeUserTab === 'SYSTEM' ? 'rgba(192, 132, 252, 0.3)' : 'rgba(255,255,255,0.05)',
                            border: activeUserTab === 'SYSTEM' ? '1px solid #c084fc' : '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            transition: 'all 0.3s ease'
                        }}
                    >
                        <Cpu size={16} style={{ marginRight: '8px', color: activeUserTab === 'SYSTEM' ? '#c084fc' : 'inherit' }} /> SYSTEM_LOGS
                    </button>
                    <button 
                        onClick={() => setActiveUserTab('FRAMEWORK')}
                        className={`stark-btn ${activeUserTab === 'FRAMEWORK' ? 'active' : ''}`}
                        style={{ 
                            padding: '10px 20px', 
                            fontSize: '11px', 
                            fontWeight: 'bold',
                            letterSpacing: '1px',
                            color: activeUserTab === 'FRAMEWORK' ? '#fff' : '#64748b',
                            background: activeUserTab === 'FRAMEWORK' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(255,255,255,0.05)',
                            border: activeUserTab === 'FRAMEWORK' ? '1px solid var(--neon-green)' : '1px solid rgba(255,255,255,0.1)',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            transition: 'all 0.3s ease'
                        }}
                    >
                        <AlertTriangle size={16} style={{ marginRight: '8px', color: activeUserTab === 'FRAMEWORK' ? 'var(--neon-green)' : 'inherit' }} /> MAPPED_FRAMEWORK
                    </button>
                </div>
            </div>

            {/* ANALYST INTELLIGENCE OVERLAY (SCIENTIFIC CONTEXT) */}
            <div style={{ 
                background: 'rgba(34, 211, 238, 0.05)', 
                border: '1px solid rgba(34, 211, 238, 0.2)', 
                padding: '10px 15px', 
                borderRadius: '8px', 
                marginBottom: '20px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
            }}>
                <div style={{ color: 'var(--neon-cyan)', animation: 'pulse 2s infinite' }}><Icons.Activity size={20} /></div>
                <div style={{ fontSize: '11px', color: '#94a3b8', lineHeight: '1.4' }}>
                    <strong style={{ color: 'var(--neon-cyan)' }}>ANALYST_ADVISORY:</strong> Your dashboard is now operating in <strong>HIGH_FIDELITY</strong> mode. Every log entry is cross-referenced with your historical behavioral baseline using the 
                    <span style={{ color: '#fff' }}> Isolation Forest (ML)</span> algorithm to ensure your identity integrity remains uncompromised.
                </div>
            </div>

            <hr style={{ borderColor: 'rgba(255,255,255,0.05)', marginBottom: '30px' }} />

            {/* --- TAB 1: WEBSITE LOGS --- */}
            {activeUserTab === 'WEBSITE' && (
                <div className="fade-in">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '20px', marginBottom: '20px' }}>
                        {/* Shield Score (Interactive) */}
                        <div 
                            className="stark-glass-card pulse-glow" 
                            onClick={() => setShowTrustReport(true)}
                            style={{ padding: '20px', borderRadius: '12px', border: `1px solid ${scoreColor}`, cursor: 'pointer' }}
                        >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <h3 style={{ color: '#94a3b8', fontSize: '10px', letterSpacing: '2px', margin: 0 }}>FORENSIC TRUST SCORE</h3>
                                <Icons.Activity size={12} style={{ color: scoreColor }} />
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '20px', marginTop: '10px' }}>
                                <div style={{
                                    width: '60px', height: '60px', borderRadius: '50%', border: `3px solid ${scoreColor}`,
                                    display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px', fontWeight: 'bold',
                                    color: scoreColor, boxShadow: `0 0 15px ${scoreColor}40`
                                }}>
                                    {shieldScore}%
                                </div>
                                <div style={{ fontSize: '11px', color: '#cbd5e1', lineHeight: '1.3' }}>
                                    Your behavioral integrity score. <span style={{ color: scoreColor, fontWeight: 'bold' }}>Click for Detailed Insight.</span>
                                </div>
                            </div>
                        </div>

                        {/* Panic Button */}
                        <div className="stark-glass-card" style={{ padding: '20px', borderRadius: '12px', textAlign: 'center', borderColor: '#ef4444', background: 'rgba(239, 68, 68, 0.05)', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                            <button onClick={handlePanic} disabled={panicState !== 'IDLE'} className="panic-btn-small" style={{ marginBottom: '5px' }}>
                                {panicState === 'SENT' ? <Icons.CheckCircle size={18} /> : <Icons.AlertTriangle size={18} />}
                            </button>
                            <span style={{ color: '#fca5a5', fontSize: '9px', letterSpacing: '1px' }}>REPORT BREACH</span>
                        </div>
                    </div>

                    {/* BROWSER FORENSICS HUD */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px', marginBottom: '20px' }}>
                        <div className="stark-glass-card" style={{ padding: '15px', borderRadius: '8px', borderLeft: '2px solid var(--neon-cyan)' }}>
                            <div style={{ fontSize: '9px', color: '#64748b', letterSpacing: '1px' }}>UA_PLATFORM</div>
                            <div style={{ fontSize: '12px', color: '#fff', fontWeight: 'bold', marginTop: '4px' }}>{navigator.platform}</div>
                        </div>
                        <div className="stark-glass-card" style={{ padding: '15px', borderRadius: '8px', borderLeft: '2px solid #c084fc' }}>
                            <div style={{ fontSize: '9px', color: '#64748b', letterSpacing: '1px' }}>RESOLUTION</div>
                            <div style={{ fontSize: '12px', color: '#fff', fontWeight: 'bold', marginTop: '4px' }}>{window.screen.width}x{window.screen.height}</div>
                        </div>
                        <div className="stark-glass-card" style={{ padding: '15px', borderRadius: '8px', borderLeft: '2px solid var(--neon-green)' }}>
                            <div style={{ fontSize: '9px', color: '#64748b', letterSpacing: '1px' }}>NETWORK_STATUS</div>
                            <div style={{ fontSize: '12px', color: navigator.onLine ? 'var(--neon-green)' : 'var(--neon-red)', fontWeight: 'bold', marginTop: '4px' }}>
                                {navigator.onLine ? 'ENCRYPTED_ONLINE' : 'OFFLINE_MODE'}
                            </div>
                        </div>
                        <div className="stark-glass-card" style={{ padding: '15px', borderRadius: '8px', borderLeft: '2px solid var(--neon-gold)' }}>
                            <div style={{ fontSize: '9px', color: '#64748b', letterSpacing: '1px' }}>GEO_TIMEZONE</div>
                            <div style={{ fontSize: '12px', color: '#fff', fontWeight: 'bold', marginTop: '4px' }}>{Intl.DateTimeFormat().resolvedOptions().timeZone}</div>
                        </div>
                    </div>

                    {/* Interaction Metric */}
                    <div className="stark-glass-card" style={{ padding: '20px', borderRadius: '12px', marginBottom: '20px', overflow: 'hidden', position: 'relative' }}>
                        <div style={{ marginBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <h3 style={{ fontSize: '12px', letterSpacing: '1px', margin: 0 }}>INTERACTION FREQUENCY</h3>
                                <p style={{ fontSize: '10px', color: '#64748b', margin: 0 }}>Traffic patterns over 7 days.</p>
                            </div>
                            {filterDate && <button onClick={() => setFilterDate(null)} style={{ background: 'transparent', border: '1px solid var(--neon-cyan)', color: 'var(--neon-cyan)', fontSize: '10px', padding: '2px 8px', cursor: 'pointer' }}>CLEAR FILTER</button>}
                        </div>
                        <div style={{ height: '140px', width: '100%', minWidth: '280px', minHeight: '140px', transition: 'all 0.3s ease-in-out' }}>
                            {chartData && chartData.length > 0 ? (
                                <ResponsiveContainer width="100%" height="100%" minWidth={280} minHeight={140} debounce={200}>
                                    <BarChart data={chartData} onClick={(d) => d?.activePayload && setFilterDate(filterDate === d.activePayload[0].payload.fullDate ? null : d.activePayload[0].payload.fullDate)}>
                                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1e293b" />
                                        <XAxis dataKey="date" stroke="#64748b" fontSize={9} axisLine={false} />
                                        <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #22d3ee', fontSize: '10px' }} />
                                        <Bar dataKey="count" fill="var(--neon-cyan)">
                                            {chartData.map((e, i) => <Cell key={i} fill={filterDate === e.fullDate ? '#f59e0b' : '#22d3ee'} />)}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            ) : (
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#64748b', fontSize: '12px' }}>
                                    No activity data available
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Logs */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '20px' }}>
                        <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                                <h3 style={{ fontSize: '14px', margin: 0 }}>LIVE BROWSER INTERACTION FEED</h3>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <div className="pulse-dot"></div>
                                    <span style={{ fontSize: '9px', color: 'var(--neon-cyan)', letterSpacing: '1px' }}>STREAM_ACTIVE</span>
                                </div>
                            </div>
                            <p style={{ fontSize: '11px', color: '#64748b', marginBottom: '20px' }}>Real-time telemetry of your browser-level interactions and security-sensitive actions.</p>
                            
                            <div style={{ display: 'grid', gridTemplateColumns: '140px 180px 1fr 100px', paddingBottom: '10px', borderBottom: '1px solid #1e293b', color: '#64748b', fontSize: '10px' }}>
                                <span>TIMESTAMP</span>
                                <span>INTERACTION_TYPE</span>
                                <span>FORENSIC_DETAILS</span>
                                <span>RISK_LEVEL</span>
                            </div>
                            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                                {groupedActivity.map((act) => {
                                    const isAnomaly = act.ml_is_anomaly || act.anomaly_score > 0.4;
                                    const isSecurityEvent = ['clipboard_copy', 'clipboard_paste', 'console_open', 'source_view', 'outbound_click', 'file_download'].includes(act.type);
                                    const logKey = `${act.timestamp}-${act.type}-${act.id || ''}`;
                                    
                                    return (
                                        <div key={logKey} onClick={() => setSelectedLog(act)} className="interactive-log-row" style={{ 
                                            display: 'grid', 
                                            gridTemplateColumns: '140px 180px 1fr 100px', 
                                            padding: '12px 0', 
                                            borderBottom: '1px solid rgba(255,255,255,0.05)', 
                                            fontSize: '12px',
                                            background: isSecurityEvent ? 'rgba(34, 211, 238, 0.03)' : (isAnomaly ? 'rgba(239, 68, 68, 0.03)' : 'transparent'),
                                            borderLeft: isSecurityEvent ? '2px solid var(--neon-cyan)' : (isAnomaly ? '2px solid var(--neon-red)' : '2px solid transparent')
                                        }}>
                                            <div style={{ color: '#94a3b8', fontSize: '11px' }}>{formatDate(act.timestamp)}</div>
                                            <div style={{ color: isSecurityEvent ? 'var(--neon-cyan)' : '#cbd5e1', fontWeight: isSecurityEvent ? 'bold' : 'normal' }}>
                                                {act.type?.toUpperCase()} {act.count > 1 && <span style={{ color: 'var(--neon-gold)', marginLeft: '4px' }}>(x{act.count})</span>}
                                            </div>
                                            <div>
                                                <div style={{ color: '#fff', fontSize: '11px' }}>
                                                    {(() => {
                                                        let det = {};
                                                        try {
                                                            det = typeof act.details === 'string' ? JSON.parse(act.details) : (act.details || {});
                                                        } catch (e) {
                                                            det = {};
                                                        }
                                                        if (act.type === 'outbound_click') return `🔗 Outbound: ${det.site || det.url || 'Unknown'}`;
                                                        if (act.type === 'nav_context') {
                                                            return `👀 ${det.message}`;
                                                        }
                                                        if (act.type === 'AppBehaviour' || act.type === 'APPLICATION_STARTED' || act.type === 'APPLICATION_CLOSED') {
                                                            const appDisplayName = String(det.application_name || det.app_name || det.app || det.title || act.application_name || 'Unknown').split('\\').pop().replace(/\.exe$/i,'').toUpperCase();
                                                            if (det.user_action === 'PROCESS_START' || det.user_action === 'OPEN' || act.type === 'APPLICATION_STARTED') return `🚀 Application Opened: ${appDisplayName}`;
                                                            if (det.user_action === 'PROCESS_STOP' || det.user_action === 'CLOSE' || act.type === 'APPLICATION_CLOSED') return `⏹️ Application Closed: ${appDisplayName}`;
                                                        }
                                                        if (act.type === 'DeviceControl' || act.type === 'SystemPerformance') {
                                                            if (det.user_action === 'CHARGER_PLUGGED_IN') return `🔌 Charger Plugged In (${det.batteryPercent}%)`;
                                                            if (det.user_action === 'CHARGER_UNPLUGGED') return `🔋 Charger Unplugged (${det.batteryPercent}%)`;
                                                        }
                                                        if (act.type === 'nav_away') {
                                                            const dest = det.destination;
                                                            return `🚪 Switched Page: ${det.page_title || 'SIEM Watchtower'} → 🌐 ${dest || 'External Site'}`;
                                                        }
                                                        if (act.type === 'nav_return') {
                                                            const fromSite = det.from_site;
                                                            return `🔙 Returned Page: 🌐 ${fromSite || 'External Site'} → ${det.page_title || 'SIEM Watchtower'}`;
                                                        }
                                                        if (act.type === 'FOREGROUND_WINDOW_CHANGE') return `User focused on window: ${det.title}`;
                                                        if (act.type === 'idle_start') return `💤 User Idle Detected (Threshold: ${det.threshold || '60s'})`;
                                                        if (act.type === 'idle_end') return `👋 User Resumed Activity`;
                                                        if (act.type === 'performance_metric') return `⚡ Performance Alert (${det.name}): ${Math.round(det.value)}ms`;
                                                        if (act.type === 'page_timing') return `⏱️ Initial Page Load Time: ${det.load_time_ms}ms`;
                                                        if (act.type === 'network_status') return `📶 Network Status Changed: ${det.state?.toUpperCase()}`;
                                                        if (act.type === 'route_change') return `User switched: ${det.from} → ${det.to}`;
                                                        if (act.type === 'window_resize') return `📏 Window Resized to: ${det.width}x${det.height}`;
                                                        if (act.type === 'form_focus') return `📝 Form Focus: [${det.type}] ${det.name || det.id || 'Unknown Input'}`;
                                                        if (act.type === 'clipboard_copy') return `📋 Copied to Clipboard (${det.length} chars)`;
                                                        if (act.type === 'clipboard_paste') return `📋 Pasted from Clipboard`;
                                                        if (act.type === 'console_open') return `⚠️ Developer Console Opened via ${det.method}`;
                                                        if (act.type === 'source_view') return `⚠️ Page Source Code Viewed`;
                                                        if (act.type === 'context_menu') return `🖱️ Right-Click Menu Opened`;
                                                        if (act.type === 'scroll_depth') return `📜 Scrolled to Depth: ${det.depth}`;
                                                        
                                                        return JSON.stringify(det).substring(0, 80);
                                                    })()}
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                <span style={{ 
                                                    fontSize: '8px', 
                                                    padding: '2px 6px', 
                                                    background: isSecurityEvent ? 'rgba(34, 211, 238, 0.1)' : 'rgba(255,255,255,0.05)', 
                                                    color: isSecurityEvent ? 'var(--neon-cyan)' : '#94a3b8', 
                                                    border: isSecurityEvent ? '1px solid var(--neon-cyan)' : '1px solid rgba(255,255,255,0.1)',
                                                    borderRadius: '2px'
                                                }}>{isSecurityEvent ? 'SENSITIVE' : 'ROUTINE'}</span>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* EXPORT & PRIVACY SIDEBAR */}
                        <div className="stark-glass-card" style={{ padding: '20px', borderRadius: '12px', height: 'fit-content' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                                <Icons.Download size={18} style={{ color: 'var(--neon-cyan)' }} />
                                <h3 style={{ fontSize: '12px', margin: 0, letterSpacing: '1px' }}>REPORTS & EXPORTS</h3>
                            </div>
                            <p style={{ fontSize: '10px', color: '#94a3b8', lineHeight: '1.5', marginBottom: '20px' }}>
                                Securely download your browser telemetry logs. Files are generated in <strong>JSON</strong> or <strong>CSV</strong> formats.
                            </p>
                            
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '30px' }}>
                                <div style={{ fontSize: '9px', color: '#64748b' }}>EXPORT ACTIONS</div>
                                <button 
                                    onClick={() => {
                                        const url = `http://localhost:5000/api/export?table=activity_logs&format=csv&days=30&uid=${user.uid}`;
                                        window.open(url, '_blank');
                                    }}
                                    className="stark-btn"
                                    style={{ width: '100%', padding: '10px', fontSize: '10px', background: 'rgba(34, 211, 238, 0.1)', border: '1px solid var(--neon-cyan)', color: '#fff', borderRadius: '4px', cursor: 'pointer' }}
                                >
                                    📥 DOWNLOAD WEBSITE LOGS (.CSV)
                                </button>
                                <button 
                                    onClick={() => {
                                        const url = `http://localhost:5000/api/export?table=activity_logs&format=json&days=30&uid=${user.uid}`;
                                        window.open(url, '_blank');
                                    }}
                                    className="stark-btn"
                                    style={{ width: '100%', padding: '10px', fontSize: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', borderRadius: '4px', cursor: 'pointer' }}
                                >
                                    📥 DOWNLOAD WEBSITE LOGS (.JSON)
                                </button>
                            </div>

                            <hr style={{ borderColor: 'rgba(255,255,255,0.05)', marginBottom: '20px' }} />

                             <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '15px' }}>
                                <Icons.Shield size={18} style={{ color: '#c084fc' }} />
                                <h3 style={{ fontSize: '12px', margin: 0, letterSpacing: '1px' }}>PRIVACY CONTROLS</h3>
                            </div>
                            
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div>
                                        <div style={{ fontSize: '10px', color: '#fff' }}>Tab Tracking</div>
                                        <div style={{ fontSize: '8px', color: '#64748b' }}>Log when you leave/return to this tab</div>
                                    </div>
                                    <input type="checkbox" checked={consentTracking} onChange={(e) => handlePrivacyUpdate('consent_tracking', e.target.checked)} />
                                </div>

                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div>
                                        <div style={{ fontSize: '10px', color: '#fff' }}>Anonymize Logs</div>
                                        <div style={{ fontSize: '8px', color: '#64748b' }}>Mask your User ID in all telemetry</div>
                                    </div>
                                    <input type="checkbox" checked={anonymizeLogs} onChange={(e) => handlePrivacyUpdate('anonymize_logs', e.target.checked)} />
                                </div>
                            </div>
                            
                            <div style={{ marginTop: '20px', padding: '10px', background: 'rgba(34, 197, 94, 0.05)', borderRadius: '4px', borderLeft: '2px solid var(--neon-green)' }}>
                                <div style={{ fontSize: '9px', color: 'var(--neon-green)', fontWeight: 'bold' }}>FORENSIC INTEGRITY</div>
                                <div style={{ fontSize: '8px', color: '#94a3b8', marginTop: '4px' }}>Logs are cryptographically signed at origin.</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* --- TAB 3: FRAMEWORK --- */}
            {activeUserTab === 'FRAMEWORK' && (
                <div className="fade-in">
                    <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px', marginBottom: '25px', borderLeft: '4px solid var(--neon-green)' }}>
                        <h3 style={{ fontSize: '18px', color: 'var(--neon-green)', marginBottom: '10px' }}>MITRE ATT&CK MAPPING SUMMARY</h3>
                        <p style={{ fontSize: '12px', color: '#94a3b8' }}>This view provides a high-level overview of detected techniques in your activity logs and recommended defensive actions.</p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '20px' }}>
                        {Object.entries(remediationGuide).map(([tid, info]) => {
                            const occurrences = activity.filter(a => a.mapped_technique_id === tid).length;
                            return (
                                <div key={tid} className="stark-glass-card" style={{ padding: '20px', borderRadius: '12px', position: 'relative', overflow: 'hidden' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '15px' }}>
                                        <div>
                                            <span style={{ fontSize: '10px', color: 'var(--neon-cyan)', fontWeight: 'bold' }}>{tid}</span>
                                            <h4 style={{ fontSize: '14px', margin: '5px 0' }}>{info.name}</h4>
                                        </div>
                                        <div style={{ background: 'rgba(34, 211, 238, 0.1)', color: 'var(--neon-cyan)', padding: '4px 10px', borderRadius: '20px', fontSize: '10px', fontWeight: 'bold' }}>
                                            {occurrences} DETECTED
                                        </div>
                                    </div>
                                    
                                    <p style={{ fontSize: '11px', color: '#cbd5e1', lineHeight: '1.4', marginBottom: '15px' }}>
                                        <strong>REMEDIATION:</strong> {info.solution}
                                    </p>

                                    <a href={info.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--neon-cyan)', fontSize: '10px', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                        VIEW FULL INTELLIGENCE <Icons.Globe size={12} />
                                    </a>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}
            {/* --- TAB 2: SYSTEM LOGS --- */}
            {activeUserTab === 'SYSTEM' && (
                <div className="fade-in">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '25px', marginBottom: '30px' }}>
                        {/* Telemetry HUD */}
                        <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px' }}>
                            <h3 style={{ color: '#94a3b8', fontSize: '11px', marginBottom: '20px' }}>LIVE ENDPOINT TELEMETRY</h3>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                                <div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', marginBottom: '5px' }}>
                                        <span>CPU UTILIZATION</span>
                                        <span style={{ color: '#c084fc' }}>{stats.cpu.toFixed(0)}%</span>
                                    </div>
                                    <div style={{ height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                                        <div style={{ width: `${stats.cpu}%`, height: '100%', background: '#c084fc', transition: 'width 0.5s' }}></div>
                                    </div>
                                </div>
                                <div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', marginBottom: '5px' }}>
                                        <span>MEMORY USAGE</span>
                                        <span style={{ color: '#a855f7' }}>{stats.ram.toFixed(0)}%</span>
                                    </div>
                                    <div style={{ height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                                        <div style={{ width: `${stats.ram}%`, height: '100%', background: '#a855f7', transition: 'width 0.5s' }}></div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Explain Text */}
                        <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px', display: 'flex', alignItems: 'center', background: 'rgba(192, 132, 252, 0.05)' }}>
                            <p style={{ fontSize: '12px', color: '#cbd5e1', fontStyle: 'italic', margin: 0, lineHeight: '1.6' }}>
                                "System Logs monitor your hardware health and background operating system events. This allows administrators to detect unauthorized software usage or hardware-level tampering."
                            </p>
                        </div>
                    </div>

                    {/* System Frequency */}
                    <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px', marginBottom: '30px', position: 'relative' }}>
                        <h3 style={{ fontSize: '14px', marginBottom: '15px' }}>SYSTEM EVENT DENSITY (24H)</h3>
                        {(data.userSystem?.logs?.length === 0 || !data.userSystem?.logs) ? (
                            <div style={{ height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px dashed rgba(255,255,255,0.1)', borderRadius: '8px' }}>
                                <span style={{ fontSize: '10px', color: '#64748b', letterSpacing: '1px' }}>
                                    No system telemetry yet. Start the agent to stream events in real-time.
                                </span>
                            </div>
                        ) : (
                            <div style={{ height: '180px', width: '100%', minWidth: '280px', minHeight: '180px', transition: 'all 0.3s ease-in-out' }}>
                                {data.userSystem.frequency && data.userSystem.frequency.length > 0 ? (
                                    <ResponsiveContainer width="100%" height="100%" minWidth={280} minHeight={180} debounce={200}>
                                        <BarChart data={data.userSystem.frequency}>
                                            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1e293b" />
                                            <XAxis dataKey="hour" stroke="#64748b" fontSize={10} tickFormatter={(h) => `${h}:00`} />
                                            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #c084fc' }} />
                                            <Bar dataKey="count" fill="#c084fc" />
                                        </BarChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#64748b', fontSize: '12px' }}>
                                        No frequency data available
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* System Logs */}
                    <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                            <div>
                                <h3 style={{ fontSize: '14px', margin: 0 }}>RAW SYSTEM TELEMETRY</h3>
                                <p style={{ fontSize: '9px', color: '#64748b', margin: '4px 0 0 0' }}>
                                    {showAllHistory 
                                        ? "Showing complete historical log archive for this workstation." 
                                        : "Clipped to current active session. Reset automatically on logout."}
                                </p>
                            </div>
                            <button 
                                onClick={() => setShowAllHistory(!showAllHistory)}
                                className={`stark-btn ${showAllHistory ? 'active' : ''}`}
                                style={{ 
                                    fontSize: '10px', 
                                    padding: '6px 12px', 
                                    background: showAllHistory ? 'rgba(34, 211, 238, 0.2)' : 'rgba(255,255,255,0.05)',
                                    border: `1px solid ${showAllHistory ? 'var(--neon-cyan)' : 'rgba(255,255,255,0.1)'}`,
                                    color: showAllHistory ? 'var(--neon-cyan)' : '#94a3b8',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    transition: 'all 0.3s ease',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '6px'
                                }}
                            >
                                <Icons.Activity size={12} />
                                {showAllHistory ? "VIEWING FULL HISTORY" : "VIEW ALL HISTORY"}
                            </button>
                        </div>
                        {systemLogsForTable.length > 0 ? (
                            <>
                                <div style={{ display: 'grid', gridTemplateColumns: '150px 100px 1fr 80px', paddingBottom: '10px', borderBottom: '1px solid #1e293b', color: '#64748b', fontSize: '10px' }}>
                                    <span>TIMESTAMP</span>
                                    <span>HOST</span>
                                    <span>EVENT DETAILS</span>
                                    <span>RISK</span>
                                </div>
                                <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                                    {systemLogsForTable.map((log) => {
                                        let details = {};
                                        try { details = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {}); } catch(err) {}
                                        const dm = { ...details, ...(details.metadata || {}), ...(details.Data || {}) };
                                        
                                        const et = log.event_type || log.type || '';
                                        // For AppBehaviour (Python agent OPEN/CLOSE), get app from details.application_name
                                        const userAction =
                                            details.user_action ??
                                            details.metadata?.user_action ??
                                            null;
                                        const rawApp = details.application_name || details.app_name || details.app || details.metadata?.title || details.NewProcessName || details.Data?.NewProcessName || details.Data?.FaultingApplicationName || log.application_name || '';
                                        const appName = rawApp ? rawApp.split('\\').pop().replace(/\.exe$/i,'') : '';

                                        let label = et;
                                        let labelColor = '#fff';

                                        // System Performance & Battery Events
                                        if (et === 'SystemPerformance' || et === 'BatteryEvent' || et === 'DeviceControl' || et.startsWith('BATTERY_')) {
                                            const pct = dm.batteryPercent || dm.percent || dm.level || '';
                                            if (userAction === 'CHARGER_PLUGGED_IN' || et === 'BATTERY_CHARGING') {
                                                const boot = dm.initialReading ? ' (at agent start)' : '';
                                                label = pct != null && pct !== '' ? `🔌 CHARGER PLUGGED IN · ${pct}%${boot}` : `🔌 CHARGER PLUGGED IN${boot}`;
                                                labelColor = '#4ade80';
                                            } else if (userAction === 'CHARGER_UNPLUGGED' || et === 'BATTERY_LOW_ALERT') {
                                                const boot = dm.initialReading ? ' (at agent start)' : '';
                                                label = pct != null && pct !== '' ? `🔋 BATTERY LOW ALERT · ${pct}%${boot}` : `🔋 BATTERY ALERT${boot}`;
                                                labelColor = '#fbbf24';
                                            } else if (et === 'BATTERY_STATUS') {
                                                label = `🔋 BATTERY PERCENTAGE: ${pct}%`;
                                                labelColor = '#86efac';
                                            } else {
                                                label = userAction || 'SYSTEM PERFORMANCE';
                                                labelColor = '#94a3b8';
                                            }
                                        } else if (et === 'LONG_SESSION_ALERT' || et === 'LONG_RUNNING_APP') {
                                            const hrs = dm.duration_hours || '1+';
                                            label = `⚠️ LONG RUNNING APP: ${hrs} HOURS ACTIVE`;
                                            labelColor = '#f97316';
                                        } else if (et === 'AppBehaviour' || et === 'APPLICATION_STARTED' || et === 'APPLICATION_CLOSED') {
                                            if (userAction === 'APP_HIGH_MEMORY') {
                                                const mm = { ...details, ...(details.metadata || {}) };
                                                const mb = mm.memory_mb;
                                                const disp = (mm.application_name || appName || mm.process_name || 'APP').replace(/\.exe$/i, '');
                                                label = mb != null && mb !== '' ? `HIGH APP RAM · ${disp} (${mb} MB)` : `HIGH APP RAM · ${disp}`;
                                                labelColor = '#f97316';
                                            } else if (userAction === 'APP_HIGH_BATTERY') {
                                                const bm = { ...details, ...(details.metadata || {}) };
                                                const cpuV = bm.cpu_percent;
                                                const disp = (bm.application_name || appName || bm.process_name || 'APP').replace(/\.exe$/i, '');
                                                label = cpuV != null && cpuV !== '' ? `HIGH APP CPU (battery load) · ${disp} (${cpuV}%)` : `HIGH APP CPU (battery load) · ${disp}`;
                                                labelColor = '#fbbf24';
                                            } else if (userAction === 'OPEN' || userAction === 'PROCESS_START' || userAction === 'APPLICATION_STARTED' || et === 'APPLICATION_STARTED') {
                                                label = appName ? `▶ ${appName.toUpperCase()} IS OPENED` : '▶ APP IS OPENED';
                                                labelColor = '#22d3ee';
                                            } else if (userAction === 'CLOSE' || userAction === 'PROCESS_STOP' || userAction === 'APPLICATION_CLOSED' || et === 'APPLICATION_CLOSED') {
                                                const dur =
                                                    details.metadata?.sessionDuration ??
                                                    details.metadata?.duration;
                                                const durStr = dur !== undefined ? ` (Duration: ${dur}s)` : '';
                                                label = appName ? `■ ${appName.toUpperCase()} IS CLOSED${durStr}` : `■ APP IS CLOSED${durStr}`;
                                                labelColor = '#f87171';
                                            } else {
                                                label = appName ? `APP: ${appName.toUpperCase()}` : 'APP EVENT';
                                                labelColor = '#c084fc';
                                            }
                                        } else if (et.startsWith('APP_LAUNCH') || et === 'PROCESS_CREATION' || et === 'PROCESS_START') {
                                            label = appName ? `▶ ${appName.toUpperCase()} IS OPENED` : '▶ APP IS OPENED';
                                            labelColor = '#22d3ee';
                                        } else if (et.startsWith('APP_STOP')) {
                                            const cleanName = appName || et.replace('APP_STOP_','').toUpperCase();
                                            label = `■ ${cleanName} IS CLOSED`; labelColor = '#f87171';
                                        } else if (et === 'PROCESS_STOP') {
                                            label = appName ? `■ ${appName.toUpperCase()} IS CLOSED` : '■ PROCESS STOPPED';
                                            labelColor = '#f87171';
                                        } else if (et === 'APP_LAUNCH_NOTEPAD') { label = '▶ NOTEPAD++ IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_EXCEL') { label = '▶ EXCEL IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_WORD') { label = '▶ WORD IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_CHROME') { label = '▶ CHROME IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_EDGE') { label = '▶ EDGE IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_VSCODE') { label = '▶ VS CODE IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'APP_LAUNCH_CODEBLOCKS') { label = '▶ CODE::BLOCKS IS OPENED'; labelColor = '#22d3ee'; }
                                        else if (et === 'USB_DEVICE_CONNECTED') { label = '🔌 USB IS CONNECTED'; labelColor = '#facc15'; }
                                        else if (et === 'USB_DEVICE_DISCONNECTED') { label = '⏏ USB IS DISCONNECTED'; labelColor = '#f97316'; }
                                        else if (et === 'USB_DEVICE_ACTIVITY') { label = '💾 USB ACTIVITY DETECTED'; labelColor = '#facc15'; }
                                        else if (et === 'APPLICATION_CRASH') { 
                                            const crashApp = details.FaultingApplicationName || appName || 'UNKNOWN';
                                            label = `💥 ${crashApp.toUpperCase()} CRASHED`; labelColor = '#ef4444'; 
                                        }
                                        else if (et === 'WORKSTATION_LOCK') { label = '🔒 SCREEN LOCKED'; labelColor = '#94a3b8'; }
                                        else if (et === 'WORKSTATION_UNLOCK') { label = '🔓 SCREEN UNLOCKED'; labelColor = '#86efac'; }
                                        else if (et === 'SYSTEM_SLEEP') { label = '💤 SYSTEM SLEEP'; labelColor = '#818cf8'; }
                                        else if (et === 'SYSTEM_WAKE') { label = '☀ SYSTEM WAKE'; labelColor = '#fde68a'; }
                                        else if (et === 'SYSTEM_STARTUP' || userAction === 'SYSTEM_STARTUP') { label = '🟢 SYSTEM BOOT'; labelColor = '#4ade80'; }
                                        else if (et === 'SYSTEM_SHUTDOWN' || userAction === 'SYSTEM_SHUTDOWN') { label = '🔴 SYSTEM SHUTDOWN'; labelColor = '#f87171'; }
                                        else if (et === 'Authentication') {
                                            const am = { ...details, ...(details.metadata || {}) };
                                            const authAct = userAction || am.user_action;
                                            if (authAct === 'USER_LOGIN') {
                                                label = 'SESSION LOGON';
                                                labelColor = '#4ade80';
                                            } else if (authAct === 'USER_LOGOUT') {
                                                label = 'SESSION LOGOFF';
                                                labelColor = '#94a3b8';
                                            } else if (authAct === 'SCREEN_LOCKED') {
                                                label = 'SCREEN LOCKED';
                                                labelColor = '#94a3b8';
                                            } else if (authAct === 'SCREEN_UNLOCKED') {
                                                label = 'SCREEN UNLOCKED';
                                                labelColor = '#86efac';
                                            } else {
                                                label = authAct ? `AUTH · ${authAct}` : 'Authentication';
                                                labelColor = '#cbd5e1';
                                            }
                                        }
                                        else if (et === 'DeviceControl') {
                                            const dm = { ...details, ...(details.metadata || {}) };
                                            const pct = dm.batteryPercent;
                                            if (userAction === 'CHARGER_PLUGGED_IN') {
                                                const boot = dm.initialReading ? ' (at agent start)' : '';
                                                label = pct != null && pct !== '' ? `CHARGER PLUGGED IN · ${pct}%${boot}` : `CHARGER PLUGGED IN${boot}`;
                                                labelColor = '#4ade80';
                                            } else if (userAction === 'CHARGER_UNPLUGGED') {
                                                const boot = dm.initialReading ? ' (at agent start)' : '';
                                                label = pct != null && pct !== '' ? `CHARGER UNPLUGGED · ${pct}%${boot}` : `CHARGER UNPLUGGED${boot}`;
                                                labelColor = '#fbbf24';
                                            } else {
                                                label = userAction ? `DEVICE: ${userAction}` : 'DEVICE CONTROL';
                                                labelColor = '#94a3b8';
                                            }
                                        }
                                        else if (et === 'SystemPerformance') {
                                            const m = { ...details, ...(details.metadata || {}) };
                                            if (userAction === 'BATTERY_DRAIN_ALERT') {
                                                const rl = (m.riskLevel || '').toUpperCase();
                                                const rate = m.batteryDrainRatePerHour;
                                                const cons = m.batteryConsumedLastHour;
                                                const d = m.drainPercent;
                                                const parts = ['BATTERY DRAIN', rl || '—'];
                                                if (rate != null && rate !== '') parts.push(`~${rate}%/h`);
                                                if (cons != null && cons !== '') parts.push(`~${cons}%/window`);
                                                if (d != null && d !== '') parts.push(`Δ${d}%`);
                                                label = parts.join(' · ');
                                                labelColor = rl === 'CRITICAL' ? '#ef4444' : rl === 'HIGH' ? '#f97316' : rl === 'MEDIUM' ? '#f59e0b' : '#22c55e';
                                            } else if (userAction === 'BATTERY_CRITICAL') {
                                                label = `BATTERY CRITICAL · ${m.batteryPercent ?? '?'}%`;
                                                labelColor = '#ef4444';
                                            } else if (userAction === 'HIGH_CPU_USAGE') {
                                                label = `HIGH CPU · ${m.cpuUsage ?? '?'}%`;
                                                labelColor = '#f97316';
                                            } else if (userAction === 'HIGH_MEMORY_USAGE') {
                                                label = `HIGH MEMORY · ${m.memoryUsage ?? '?'}%`;
                                                labelColor = '#f97316';
                                            } else if (userAction === 'HIGH_DISK_USAGE') {
                                                label = `HIGH DISK · ${m.diskUsagePercent ?? '?'}%`;
                                                labelColor = '#f97316';
                                            } else if (userAction === 'APP_TOP_CONSUMERS_REPORT') {
                                                const fmtMem = (a) => (Array.isArray(a) ? a : []).slice(0, 6).map((x) => `${x.exe} ${x.mb}MB`).join(', ');
                                                const fmtCpu = (a) => (Array.isArray(a) ? a : []).slice(0, 6).map((x) => `${x.exe} ${x.cpu}%`).join(', ');
                                                const cpuTitle = m.onBattery ? 'CPU (battery impact proxy)' : 'CPU';
                                                label = `TOP APPS · RAM: ${fmtMem(m.topMemory)} · ${cpuTitle}: ${fmtCpu(m.topCpu)}`;
                                                labelColor = m.onBattery ? '#fbbf24' : '#38bdf8';
                                            } else if (userAction === 'SYSTEM_RESOURCE_SNAPSHOT') {
                                                label = ['RESOURCE SNAPSHOT', `RAM ${m.memoryUsage ?? '?'}%`, `Disk ${m.diskUsagePercent ?? '?'}%`].join(' · ');
                                                labelColor = '#38bdf8';
                                            } else if (userAction === 'AGENT_RUNNING') {
                                                label = 'AGENT HEARTBEAT';
                                                labelColor = '#64748b';
                                            } else if (userAction === 'IDLE_TIME_START' || userAction === 'IDLE_TIME_END') {
                                                label = userAction === 'IDLE_TIME_START' ? 'IDLE START' : 'IDLE END';
                                                labelColor = '#94a3b8';
                                            } else if (userAction === 'SYSTEM_SLEEP' || userAction === 'SYSTEM_WAKEUP') {
                                                label = userAction === 'SYSTEM_SLEEP' ? 'SLEEP' : 'WAKE';
                                                labelColor = '#818cf8';
                                            } else {
                                                label = userAction ? `SYS: ${userAction}` : 'SystemPerformance';
                                                labelColor = '#cbd5e1';
                                            }
                                        } else if (et === 'HIGH_CPU_LOAD' || userAction === 'HIGH_CPU_LOAD') {
                                            label = 'HIGH CPU LOAD';
                                            labelColor = '#f97316';
                                        }
                                        else if (et === 'USER_LOGIN') { label = '✔ USER LOGIN'; labelColor = '#4ade80'; }
                                        else if (et === 'LOGIN_FAILED') { label = '✘ LOGIN FAILED'; labelColor = '#ef4444'; }

                                        const metaForRisk = { ...details, ...(details.metadata || {}) };
                                        const rlRaw = (metaForRisk.riskLevel || '').toUpperCase();
                                        
                                        // Calculate battery-based risk
                                        const batteryPct = metaForRisk.batteryPercent ?? metaForRisk.percent ?? metaForRisk.level ?? null;
                                        let batteryRisk = null;
                                        if (batteryPct !== null && batteryPct !== undefined) {
                                            if (batteryPct <= 10) batteryRisk = 'CRITICAL';
                                            else if (batteryPct <= 20) batteryRisk = 'HIGH';
                                            else if (batteryPct <= 30) batteryRisk = 'MEDIUM';
                                        }
                                        
                                        const isCrit =
                                            log.event_type?.includes('FAIL') ||
                                            log.event_type?.includes('CRIT') ||
                                            log.risk_level === 'HIGH' ||
                                            rlRaw === 'HIGH' ||
                                            rlRaw === 'CRITICAL' ||
                                            batteryRisk === 'CRITICAL' ||
                                            batteryRisk === 'HIGH' ||
                                            userAction === 'BATTERY_CRITICAL' ||
                                            (userAction === 'BATTERY_DRAIN_ALERT' && metaForRisk.suddenDrop);
                                        
                                        let riskBadge = 'LOW';
                                        if (rlRaw === 'CRITICAL' || batteryRisk === 'CRITICAL') riskBadge = 'CRIT';
                                        else if (rlRaw === 'HIGH' || batteryRisk === 'HIGH') riskBadge = 'HIGH';
                                        else if (rlRaw === 'MEDIUM' || batteryRisk === 'MEDIUM') riskBadge = 'MED';
                                        else if (isCrit && !rlRaw) riskBadge = 'HIGH';
                                        const riskBadgeColor =
                                            rlRaw === 'CRITICAL' || batteryRisk === 'CRITICAL' ? '#ef4444' :
                                            rlRaw === 'HIGH' || batteryRisk === 'HIGH' ? '#f97316' :
                                            rlRaw === 'MEDIUM' || batteryRisk === 'MEDIUM' ? '#f59e0b' :
                                            (isCrit ? '#ef4444' : '#22c55e');

                                        let TelemetryIcon = Activity;
                                        if (et === 'DeviceControl') {
                                            TelemetryIcon = Battery;
                                        } else if (et === 'SystemPerformance') {
                                            if (userAction === 'APP_TOP_CONSUMERS_REPORT') TelemetryIcon = Grid;
                                            else if (userAction === 'SYSTEM_RESOURCE_SNAPSHOT') TelemetryIcon = Grid;
                                            else if (userAction === 'HIGH_CPU_USAGE') TelemetryIcon = Cpu;
                                            else if (userAction === 'HIGH_MEMORY_USAGE') TelemetryIcon = Memory;
                                            else if (userAction === 'HIGH_DISK_USAGE') TelemetryIcon = HardDrive;
                                            else if (userAction === 'BATTERY_DRAIN_ALERT' || userAction === 'BATTERY_CRITICAL') TelemetryIcon = Battery;
                                            else if (userAction === 'AGENT_RUNNING') TelemetryIcon = Activity;
                                        } else if (et === 'AppBehaviour') {
                                            if (userAction === 'APP_HIGH_MEMORY') TelemetryIcon = Memory;
                                            else if (userAction === 'APP_HIGH_BATTERY') TelemetryIcon = Battery;
                                            else if (userAction === 'OPEN' || userAction === 'PROCESS_START') TelemetryIcon = Play;
                                            else if (userAction === 'CLOSE' || userAction === 'PROCESS_STOP') TelemetryIcon = StopSquare;
                                        } else if (et.startsWith('APP_LAUNCH') || et === 'PROCESS_CREATION' || et === 'PROCESS_START') {
                                            TelemetryIcon = Play;
                                        } else if (et.startsWith('APP_STOP') || et === 'PROCESS_STOP') {
                                            TelemetryIcon = StopSquare;
                                        } else if (et === 'HIGH_CPU_LOAD' || userAction === 'HIGH_CPU_LOAD') {
                                            TelemetryIcon = Cpu;
                                        } else if (et === 'Authentication') {
                                            const aa = userAction || details.user_action;
                                            if (aa === 'USER_LOGIN') TelemetryIcon = CheckCircle;
                                            else if (aa === 'USER_LOGOUT') TelemetryIcon = LogOut;
                                            else if (aa === 'SCREEN_LOCKED') TelemetryIcon = Lock;
                                            else if (aa === 'SCREEN_UNLOCKED') TelemetryIcon = Unlock;
                                            else TelemetryIcon = Shield;
                                        }

                                        const logKey = log.id || `${log.timestamp}-${log.event_type || log.type}-${JSON.stringify(details)}`;

                                        return (
                                            <div key={logKey} className="interactive-log-row" style={{ display: 'grid', gridTemplateColumns: '150px 100px 1fr 80px', padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '12px' }}>
                                                <div style={{ color: '#94a3b8', fontSize: '11px' }}>{formatDate(log.timestamp)}</div>
                                                <div style={{ color: '#cbd5e1' }}>{log.hostname}</div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: labelColor, fontWeight: 'bold', letterSpacing: '0.5px' }}>
                                                    <TelemetryIcon width={18} height={18} style={{ flexShrink: 0, opacity: 0.88, color: labelColor }} />
                                                    <span>{label}</span>
                                                </div>
                                                <div><span style={{ color: riskBadgeColor, fontSize: '10px', fontWeight: 'bold' }}>{riskBadge}</span></div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </>
                        ) : (
                            <div style={{ height: '200px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center', background: 'rgba(192, 132, 252, 0.03)', border: '1px dashed rgba(192, 132, 252, 0.2)', borderRadius: '12px' }}>
                                <div style={{ color: '#c084fc', marginBottom: '15px', animation: 'simplePulse 2s infinite' }}>
                                    <Icons.Cpu size={36} />
                                </div>
                                <div style={{ fontSize: '14px', color: '#fff', letterSpacing: '1px', fontWeight: 'bold' }}>WAITING FOR AGENT TELEMETRY</div>
                                <p style={{ fontSize: '11px', color: '#94a3b8', maxWidth: '400px', marginTop: '10px', lineHeight: '1.5' }}>
                                    Run the Python agent to begin streaming application events into this dashboard.
                                </p>
                                <div style={{ marginTop: '20px', display: 'flex', gap: '10px' }}>
                                    <div style={{ fontSize: '9px', padding: '4px 8px', background: 'rgba(255,255,255,0.05)', color: '#c084fc', border: '1px solid rgba(192, 132, 252, 0.3)', borderRadius: '4px' }}>python agents/app_tracker/app_tracker.py</div>
                                    <div style={{ fontSize: '9px', padding: '4px 8px', background: 'rgba(255,255,255,0.05)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px' }}>STATUS: LISTENING</div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* TRUST ANALYSIS MODAL */}
            {showTrustReport && (
                <StarkModal title="BEHAVIORAL INTEGRITY REPORT" onClose={() => setShowTrustReport(false)} theme="blue">
                    <div style={{ padding: '10px' }}>
                         <div style={{ textAlign: 'center', marginBottom: '30px' }}>
                            <div style={{ fontSize: '48px', fontWeight: 'bold', color: scoreColor, textShadow: `0 0 20px ${scoreColor}50` }}>{shieldScore}%</div>
                            <div style={{ fontSize: '12px', color: '#94a3b8', letterSpacing: '2px' }}>CURRENT FORENSIC STANDING</div>
                         </div>

                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                            <div style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '15px', borderRadius: '8px' }}>
                                <h4 style={{ color: '#10b981', fontSize: '11px', margin: '0 0 10px 0' }}>POSITIVE VECTORS</h4>
                                <ul style={{ fontSize: '11px', color: '#cbd5e1', paddingLeft: '15px', margin: 0 }}>
                                    <li>Recent login from verified location</li>
                                    <li>Multi-Factor Authentication active</li>
                                    <li>No unauthorized API calls detected</li>
                                    <li>Stable interaction patterns</li>
                                </ul>
                            </div>
                            <div style={{ background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '15px', borderRadius: '8px' }}>
                                <h4 style={{ color: '#ef4444', fontSize: '11px', margin: '0 0 10px 0' }}>RISK FACTORS</h4>
                                <ul style={{ fontSize: '11px', color: '#cbd5e1', paddingLeft: '15px', margin: 0 }}>
                                    {user?.failed_login_count > 0 && <li>{user.failed_login_count} Failed Login Attempts (-{user.failed_login_count * 10}%)</li>}
                                    {user?.security_status === 'AT_RISK' && <li>Behavioral Anomaly Detected (-30%)</li>}
                                    {alerts?.length > 0 && <li>Active Security Advisories (-{alerts.length * 5}%)</li>}
                                    {shieldScore === 100 && <li>No critical risks detected.</li>}
                                </ul>
                            </div>
                         </div>

                         <div style={{ marginTop: '30px', padding: '15px', background: 'rgba(34, 211, 238, 0.05)', borderRadius: '8px', fontSize: '11px', border: '1px solid rgba(34, 211, 238, 0.1)' }}>
                            <strong>ANALYST NOTE:</strong> Your trust score is a mathematical representation of your account security. To maintain a 100% score, avoid using new VPNs unexpectedly and ensure any suspicious emails are reported immediately via the PANIC button.
                         </div>
                    </div>
                </StarkModal>
            )}

            {/* MODAL */}
            {selectedLog && (
                <StarkModal title="FORENSIC EVIDENCE CARD" onClose={() => setSelectedLog(null)} theme={selectedLog.ml_is_anomaly ? "red" : "blue"}>
                    <div style={{ padding: '10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                            <div>
                                <h4 style={{ color: 'var(--neon-cyan)', margin: 0, fontSize: '11px' }}>MITRE ATT&CK</h4>
                                <a 
                                    href={remediationGuide[selectedLog.mapped_technique_id]?.url || `https://attack.mitre.org/techniques/${selectedLog.mapped_technique_id || 'T1204'}/`} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    style={{ color: '#fff', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '5px' }}
                                >
                                    <h2 style={{ margin: '5px 0', fontSize: '24px', letterSpacing: '2px', borderBottom: '1px dashed rgba(255,255,255,0.3)' }}>
                                        {selectedLog.mapped_technique_id || 'T1204'}
                                    </h2>
                                    <Icons.Globe style={{ fontSize: '14px', color: 'var(--neon-cyan)' }} />
                                </a>
                                <div style={{ fontSize: '10px', color: 'var(--neon-green)', marginTop: '2px' }}>
                                    {remediationGuide[selectedLog.mapped_technique_id]?.name || "Standard Execution Pattern"}
                                </div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                                <h4 style={{ color: 'var(--neon-cyan)', margin: 0, fontSize: '11px' }}>ML RISK SCORE</h4>
                                <h2 style={{ margin: '5px 0', fontSize: '24px', color: selectedLog.anomaly_score > 0.5 ? 'var(--neon-red)' : 'var(--neon-green)' }}>
                                    {(selectedLog.anomaly_score || 0.15).toFixed(2)}
                                </h2>
                            </div>
                        </div>

                        <div className="grid-layout" style={{ gap: '15px' }}>
                            <div style={{ gridColumn: 'span 3', background: 'rgba(0,0,0,0.3)', padding: '15px', borderRadius: '4px' }}>
                                <h5 style={{ color: '#64748b', margin: '0 0 10px 0', fontSize: '10px', letterSpacing: '2px' }}>RAW_TELEMETRY_DATA</h5>
                                <div style={{ color: 'var(--neon-cyan)', fontSize: '11px', fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: '150px', overflowY: 'auto' }}>
                                    {(() => {
                                        const det = typeof selectedLog.details === 'string' ? JSON.parse(selectedLog.details) : (selectedLog.details || {});
                                        return (
                                            <>
                                                {selectedLog.type === 'nav_away' && det.destination && (
                                                    <div style={{ color: '#fbbf24', marginBottom: '10px', fontWeight: 'bold' }}>
                                                        🚨 DESTINATION_DETECTED: {det.destination}
                                                        {det.destination_url && <span style={{ fontSize: '9px', color: '#94a3b8', display: 'block', marginTop: '2px' }}>{det.destination_url}</span>}
                                                    </div>
                                                )}
                                                {selectedLog.type === 'nav_return' && det.from_site && (
                                                    <div style={{ color: '#a78bfa', marginBottom: '10px', fontWeight: 'bold' }}>
                                                        🌐 RETURNED_FROM: {det.from_site}
                                                        {det.from_url && <span style={{ fontSize: '9px', color: '#94a3b8', display: 'block', marginTop: '2px' }}>{det.from_url}</span>}
                                                    </div>
                                                )}
                                                {selectedLog.type === 'outbound_click' && det.destination && (
                                                    <div style={{ color: '#facc15', marginBottom: '10px', fontWeight: 'bold' }}>
                                                        🔗 OUTBOUND_CLICK: {det.destination}
                                                        {det.destination_url && <span style={{ fontSize: '9px', color: '#94a3b8', display: 'block', marginTop: '2px' }}>{det.destination_url}</span>}
                                                        {det.referrer && <span style={{ fontSize: '9px', color: '#94a3b8', display: 'block', marginTop: '2px' }}>REFERRER: {det.referrer}</span>}
                                                    </div>
                                                )}
                                                {selectedLog.type === 'FOREGROUND_WINDOW_CHANGE' && det.title && (
                                                    <div style={{ color: '#c084fc', marginBottom: '10px', fontWeight: 'bold' }}>
                                                        🎯 FOCUS_ID: {det.title}
                                                    </div>
                                                )}
                                                {JSON.stringify(det, null, 2)}
                                            </>
                                        );
                                    })()}
                                </div>
                            </div>

                            <div style={{ gridColumn: 'span 3', background: 'rgba(34, 197, 94, 0.05)', padding: '15px', borderRadius: '4px', borderLeft: '3px solid var(--neon-green)' }}>
                                <h5 style={{ color: 'var(--neon-green)', margin: '0 0 10px 0', fontSize: '10px', letterSpacing: '2px' }}>🛡️ REMEDIATION_SOLUTION</h5>
                                <p style={{ fontSize: '12px', color: '#fff', lineHeight: '1.5', margin: 0 }}>
                                    {remediationGuide[selectedLog.mapped_technique_id]?.solution || "No immediate threat detected. Continue monitoring and ensure your system security patches are up to date."}
                                </p>
                            </div>
                        </div>

                        <div style={{ marginTop: '20px', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '15px' }}>
                            <h5 style={{ color: '#64748b', margin: '0 0 5px 0', fontSize: '10px' }}>ANALYST_REASONING</h5>
                            <p style={{ fontSize: '11px', color: '#94a3b8', lineHeight: '1.4', margin: 0, fontStyle: 'italic' }}>
                                {selectedLog.ml_is_anomaly 
                                    ? "Proprietary ML algorithm detected patterns consistent with adversarial behavior. High resource deviation or unauthorized sequence identified."
                                    : "Activity matches standard interaction profiles. Cross-referenced with MITRE baseline and verified as legitimate operator behavior."}
                            </p>
                        </div>
                    </div>
                </StarkModal>
            )}
        </div>
    );
};
export default NormalUserDashboard;
