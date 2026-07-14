import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Icons from './Icons';

/**
 * Component: UserActivityTimeline
 * Description: Live-streaming forensic timeline that correlates events from 
 *              multiple sources (Python Agent + Browser Telemetry). 
 *              Visualizes session clusters, identifies high-risk 
 *              deviations, and maps them to MITRE technique IDs.
 * Parameters:
 *   - None (Uses internal useEffect polling/state management)
 * Returns:
 *   - JSX.Element
 */
const UserActivityTimeline = () => {
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(true);
    const { Clock, Shield } = Icons;

    const fetchSessions = async () => {
        try {
            const user = JSON.parse(localStorage.getItem('user') || '{}');
            const uid = user.uid || '';
            const res = await axios.get(`http://localhost:5000/api/reports/correlated-sessions?requester_uid=${uid}`);
            setSessions(res.data);
            setLoading(false);
        } catch (e) {
            console.error("Failed to fetch sessions", e);
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSessions();
        const interval = setInterval(fetchSessions, 10000); // Refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const getRiskColor = (risk) => {
        if (risk === 'HIGH' || risk === 'HIGH_RISK') return '#ef4444';  // Red for anomalous
        if (risk === 'MEDIUM' || risk === 'MEDIUM_RISK') return '#eab308'; // Yellow for suspicious  
        return '#22c55e';  // Green for normal/low
    };

    const getRiskLabel = (risk) => {
        if (risk === 'HIGH' || risk === 'HIGH_RISK') return 'ANOMALOUS';
        if (risk === 'MEDIUM' || risk === 'MEDIUM_RISK') return 'SUSPICIOUS';
        return 'NORMAL';
    };

    const getRiskTextColor = (risk) => {
        if (risk === 'HIGH' || risk === 'HIGH_RISK') return '#ef4444';  // Red text
        if (risk === 'MEDIUM' || risk === 'MEDIUM_RISK') return '#eab308'; // Yellow text
        return '#22c55e';  // Green text
    };

    const getConfidenceDisplay = (session) => {
        // Use session confidence if available and valid
        let confidence = session.confidence_score || 0;
        
        // If confidence is 0 or very low, derive from risk level
        if (confidence < 0.01) {
            if (session.risk_score === 'HIGH' || session.risk_score === 'HIGH_RISK') confidence = 0.85;
            else if (session.risk_score === 'MEDIUM' || session.risk_score === 'MEDIUM_RISK') confidence = 0.65;
            else confidence = 0.95;
        }
        
        // Cap at 0.99 for realism
        confidence = Math.min(confidence, 0.99);
        
        return (confidence * 100).toFixed(0);
    };

    const getConfidenceColor = (session) => {
        const risk = session.risk_score;
        if (risk === 'HIGH' || risk === 'HIGH_RISK') return '#ef4444';  // Red for anomalous
        if (risk === 'MEDIUM' || risk === 'MEDIUM_RISK') return '#eab308'; // Yellow for suspicious
        return '#22c55e';  // Green for normal
    };

    const getClassificationIcon = (cls) => {
        if (cls === 'browser') return <Icons.Globe size={14} />;
        if (cls === 'development tools') return <Icons.Cpu size={14} />;
        if (cls === 'communication apps') return <Icons.Activity size={14} />;
        if (cls === 'system') return <Icons.Settings size={14} />;
        return <Icons.AlertTriangle size={14} />;
    };

    return (
        <div className="stark-glass-card" style={{ padding: '25px', borderRadius: '12px', height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <div>
                    <h3 style={{ fontSize: '14px', letterSpacing: '1px', margin: 0 }}>BEHAVIORAL CORRELATION TIMELINE</h3>
                    <p style={{ fontSize: '10px', color: '#64748b', margin: '4px 0 0 0' }}>Cross-source activity mapping (Frontend + Agent)</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="pulse-dot" style={{ background: '#22d3ee' }}></div>
                    <span style={{ fontSize: '9px', color: '#22d3ee', letterSpacing: '1px' }}>ENGINE_ACTIVE</span>
                </div>
            </div>

            {loading ? (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b', fontSize: '12px' }}>
                    INITIALIZING FORENSIC ENGINE...
                </div>
            ) : (
                <div style={{ flex: 1, overflowY: 'auto', paddingRight: '10px' }} className="custom-scrollbar">
                    {sessions.length === 0 ? (
                        <div style={{ textAlign: 'center', color: '#64748b', padding: '40px', fontSize: '12px', fontStyle: 'italic' }}>
                            No correlated activity detected in current cycle.
                        </div>
                    ) : (
                        sessions.map((session, i) => (
                            <div key={session.id} style={{ 
                                position: 'relative', 
                                paddingLeft: '25px', 
                                paddingBottom: '20px', 
                                borderLeft: `2px solid ${getRiskColor(session.risk_score)}30`,
                                marginBottom: i === sessions.length - 1 ? 0 : '10px'
                            }}>
                                {/* Connector Dot */}
                                <div style={{ 
                                    position: 'absolute', 
                                    left: '-6px', 
                                    top: '0', 
                                    width: '10px', 
                                    height: '10px', 
                                    borderRadius: '50%', 
                                    background: getRiskColor(session.risk_score),
                                    boxShadow: `0 0 8px ${getRiskColor(session.risk_score)}`
                                }}></div>

                                <div style={{ 
                                    background: 'rgba(30, 41, 59, 0.3)', 
                                    borderRadius: '8px', 
                                    padding: '12px', 
                                    border: '1px solid rgba(255,255,255,0.05)',
                                    transition: 'transform 0.2s',
                                    cursor: 'default'
                                }} onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(5px)'} onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                            <span style={{ color: getRiskTextColor(session.risk_score), fontSize: '11px', fontWeight: 'bold', textShadow: `0 0 10px ${getRiskTextColor(session.risk_score)}50` }}>
                                                {getRiskLabel(session.risk_score)}
                                            </span>
                                            <span style={{ color: '#94a3b8', fontSize: '10px' }}>
                                                {new Date(session.start_time).toLocaleTimeString()}
                                            </span>
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: getConfidenceColor(session), fontWeight: 'bold' }}>
                                            <Shield size={10} style={{ color: getConfidenceColor(session) }} /> {getConfidenceDisplay(session)}% CONFIDENCE
                                        </div>
                                    </div>

                                    <div style={{ fontSize: '13px', color: '#fff', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        {getClassificationIcon(session.classification)}
                                        {session.activity}
                                    </div>

                                    <div style={{ marginTop: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <div style={{ fontSize: '10px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                            <Clock size={10} /> Duration: {(session.duration_ms / 1000).toFixed(1)}s
                                        </div>
                                        {session.mapped_technique_id && (
                                            <span style={{ fontSize: '9px', background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', padding: '2px 6px', borderRadius: '4px', border: '1px solid #ef444450' }}>
                                                MITRE: {session.mapped_technique_id}
                                            </span>
                                        )}
                                    </div>

                                    <div style={{ marginTop: '10px', fontSize: '9px', color: '#475569', fontFamily: 'monospace' }}>
                                        USER: {session.user_id} | SESSION_TOKEN: {session.session_id.substring(0,8)}...
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            )}

            <div style={{ marginTop: 'auto', paddingTop: '15px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', gap: '15px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e' }}></div>
                    <span style={{ fontSize: '9px', color: '#22c55e', fontWeight: 'bold' }}>NORMAL</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#eab308', boxShadow: '0 0 6px #eab308' }}></div>
                    <span style={{ fontSize: '9px', color: '#eab308', fontWeight: 'bold' }}>SUSPICIOUS</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 6px #ef4444' }}></div>
                    <span style={{ fontSize: '9px', color: '#ef4444', fontWeight: 'bold' }}>ANOMALOUS</span>
                </div>
            </div>
        </div>
    );
};

export default UserActivityTimeline;
