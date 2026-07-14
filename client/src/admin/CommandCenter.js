import React, { useState, useEffect } from 'react';
import Icons from '../components/Icons';

// Sub-component tailored specifically for SOC analysts to monitor real time stream and issue machine commands remotely
const CommandCenter = ({ data, activeThreats }) => {
    const [matrixLogs, setMatrixLogs] = useState([]);
    const [points, setPoints] = useState([]);
    const [autoDefend, setAutoDefend] = useState(false);
    
    // 0. Fetch Auto-Defend Status
    // Lifecycle hook polling backend to ascertain the live trigger readiness state of automated threat mitigation
    useEffect(() => {
        fetch('http://localhost:5000/api/agent/auto-defend/status')
            .then(res => res.json())
            .then(res => setAutoDefend(res.enabled))
            .catch(err => console.warn("SOC: Auto-Defend status link offline", err));
    }, []);
    
    // 1. Matrix Log Stream Effect (Filtered for Significance)
    // Dynamic stream builder ignoring system noise to populate the real-time matrix feed HUD solely with security significance
    useEffect(() => {
        const allLogs = [...(data.web.logs || []), ...(data.system.logs || [])];
        // Filter out noisy telemetry (performance, navigation pings, idle states)
        const relevant = allLogs.filter(log => {
            const type = (log.event_type || log.action_type || '').toLowerCase();
            return !type.includes('performance') && 
                   !type.includes('nav_') && 
                   !type.includes('idle_') &&
                   !type.includes('battery');
        });
        const sorted = relevant.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 15);
        setMatrixLogs(sorted);
    }, [data.web.logs, data.system.logs]);

    // 2. Mock Global Map "Pings"
    // Visual orchestrator deploying aesthetic pings across the target UI globe overlay mapping traffic volume and threats randomly 
    useEffect(() => {
        if (matrixLogs.length > 0) {
            const newPoint = {
                id: Date.now(),
                x: Math.random() * 80 + 10, // 10% to 90%
                y: Math.random() * 60 + 20, // 20% to 80%
                type: matrixLogs[0].mapped_technique_id ? 'threat' : 'traffic'
            };
            setPoints(prev => [...prev.slice(-10), newPoint]);
        }
    }, [matrixLogs]);

    return (
        <div className="soc-center">
            {/* TOP BAR EXCLUSIVE FOR SOC */}
            <div className="soc-header">
                <div className="soc-title">
                    <span className="pulse-dot"></span>
                    STRATEGIC OPERATIONS COMMAND (SOC)
                </div>
                <div className="soc-metrics">
                    <div className="soc-stat">
                        <div className="label">UPLINK</div>
                        <div className="value status-online">ACTIVE</div>
                    </div>
                    <div className="soc-stat">
                        <div className="label">SYSTEM_STATUS</div>
                        <div className="value" style={{ color: 'var(--neon-green)' }}>
                            {data.stats?.threats > 5 ? 'ACTIVE MONITOR' : 'OPTIMAL'}
                        </div>
                    </div>
                </div>
            </div>

            <div className="soc-grid">
                {/* LEFT: MATRIX HUD */}
                <div className="matrix-hud card">
                    <div className="card-header">
                        <Icons.Activity /><span>LIVE ATTACK STREAM</span>
                    </div>
                    <div className="matrix-stream">
                        {matrixLogs.map((log, i) => (
                            <div key={i} className={`matrix-line ${log.mapped_technique_id ? 'is-threat' : ''} ${log.action_type === 'USER_REPORT' ? 'is-user-report' : ''}`}>
                                <span className="m-time">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                                <span className="m-type">
                                    {log.action_type === 'USER_REPORT' ? 'CITIZEN_ALERT' : (log.event_type || log.action_type)}:
                                </span>
                                <span className="m-msg">
                                    {log.action_type === 'USER_REPORT' ? `[HUMAN_SOURCE] » Suspicious Activity: ${JSON.parse(log.details).comment}` : `${log.hostname || 'WEB_FRONTEND'} » ${log.mapped_technique_id || 'T1204'}`}
                                </span>
                                {log.mapped_technique_id && log.action_type !== 'USER_REPORT' && <span className="m-alert">!! DETECTED !!</span>}
                                {log.action_type === 'USER_REPORT' && <span className="m-alert" style={{ background: 'var(--neon-gold)' }}>!! VERIFY !!</span>}
                            </div>
                        ))}
                        <div className="matrix-cursor">_</div>
                    </div>
                </div>

                {/* CENTER: THREAT MAP (SIMPLIFIED) */}
                <div className="threat-map-container card">
                    <div className="card-header">
                        <Icons.Globe /><span>INCIDENT DISTRIBUTION</span>
                    </div>
                    <div className="world-map">
                        {/* Minimalist Grid */}
                        <div className="map-grid" style={{ opacity: 0.1 }}></div>
                        
                        {/* Background Decoration */}
                        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '80%', height: '80%', border: '1px dashed rgba(14,165,233,0.1)', borderRadius: '50%' }}></div>

                        {/* Animated Points */}
                        {points.map(p => (
                            <div key={p.id} className={`map-ping ${p.type}`} style={{ left: `${p.x}%`, top: `${p.y}%` }}>
                                <div className="ping-ring" style={{ animationDuration: '3s' }}></div>
                                <div className="ping-core"></div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* RIGHT: COMMAND & CONTROL */}
                <div className="c2-panel card">
                    <div className="card-header">
                        <Icons.Cpu /><span>AGENT COMMAND & CONTROL (C2)</span>
                    </div>
                    
                    {/* AUTO-DEFEND TOGGLE */}
                    <div className="auto-defend-banner">
                        <div className="ad-info">
                            <span className="ad-label">AUTO-DEFEND PROTOCOL</span>
                            <span className={`ad-status ${autoDefend ? 'armed' : 'disarmed'}`}>
                                {autoDefend ? 'ARMED' : 'DISARMED'}
                            </span>
                        </div>
                        <button 
                            className={`ad-toggle ${autoDefend ? 'active' : ''}`}
                            onClick={toggleAutoDefend}
                        >
                            {autoDefend ? 'DISABLE' : 'ENABLE'}
                        </button>
                    </div>

                    <div className="host-list">
                        {data.userList && data.userList.filter(u => u.type === 'HOST').map((h, i) => (
                            <div key={i} className="c2-host-item">
                                <div className="h-info">
                                    <Icons.Cpu style={{ width: 14, color: h.status === 'online' ? 'var(--neon-green)' : '#64748b' }} />
                                    <span className="h-name">{h.email?.split('-')[0]}</span>
                                </div>
                                <div className="h-actions">
                                    <button className="c2-btn lock" onClick={() => sendCommand(h.email, 'LOCK')}>LOCK</button>
                                    <button className="c2-btn kill" onClick={() => promptKill(h.email)}>KILL</button>
                                </div>
                            </div>
                        ))}
                        {(!data.userList || data.userList.filter(u => u.type === 'HOST').length === 0) && (
                            <div style={{ color: '#64748b', fontSize: '10px', textAlign: 'center', padding: '20px' }}>
                                NO ACTIVE AGENTS
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );

    // Core C2 execution wrapper. Transmits specific payloads indicating actions (LOCK, MSG, KILL) via backend API to remote hosts globally
    function sendCommand(hostname, command, params = {}) {
        const confirmMsg = `EXECUTE ${command} ON ${hostname}?`;
        if (!window.confirm(confirmMsg)) return;

        fetch('http://localhost:5000/api/agent/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hostname, command, params })
        })
        .then(res => res.json())
        .then(res => {
            alert(`Command Queued: ${res.id}`);
        })
        .catch(err => {
            console.error("SOC: Command Uplink Failed", err);
            alert("Command Failed: Connection Lost");
        });
    }

    // Toggles the backend configuration enabling logical branch where AI detections autonomously dispatch mitigation commands
    function toggleAutoDefend() {
        const newState = !autoDefend;
        fetch('http://localhost:5000/api/agent/auto-defend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: newState })
        })
        .then(res => res.json())
        .then(res => setAutoDefend(res.enabled))
        .catch(err => {
            console.error("SOC: Auto-Defend toggle failed", err);
            alert("Protocol Update Failed: Server Offline");
        });
    }

    // Interface prompt collecting explicit Process ID targeted for remote termination utilizing sendCommand
    function promptKill(hostname) {
        const pid = window.prompt(`Enter PID to terminate on ${hostname}:`);
        if (pid) {
            const name = window.prompt(`Enter Process Name (for logs) or leave blank:`);
            sendCommand(hostname, 'KILL_PROC', { pid: parseInt(pid), name: name || 'Remote Kill' });
        }
    }

    // eslint-disable-next-line no-unused-vars
    // Displays modal taking human input broadcasting a system alert message overlay via system command
    function promptMsg(hostname) {
        const text = window.prompt(`Enter message for ${hostname}:`);
        if (text) sendCommand(hostname, 'MSG', { text, title: 'SOC COMMAND CENTER' });
    }
};

export default CommandCenter;
