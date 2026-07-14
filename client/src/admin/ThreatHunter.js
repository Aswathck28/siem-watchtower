import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const API = 'http://localhost:5000';

const SEV_COLOR = {
    CRITICAL: { bg: 'rgba(239,68,68,0.15)', border: '#ef4444', text: '#ef4444' },
    HIGH:     { bg: 'rgba(249,115,22,0.15)', border: '#f97316', text: '#f97316' },
    MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  border: '#eab308', text: '#eab308' },
    LOW:      { bg: 'rgba(34,197,94,0.15)',  border: '#22c55e', text: '#22c55e' },
};

// Generates dynamic span colored corresponding intelligently to parsed severity rating string
const SeverityBadge = ({ sev }) => {
    // Ensure typo-resilience by normalizing the string (removes whitespace, ignores case)
    const normalizedSev = sev ? sev.trim().toUpperCase().replace('CRITTCAL', 'CRITICAL') : 'LOW';
    const c = SEV_COLOR[normalizedSev] || SEV_COLOR.LOW;
    return (
        <span style={{
            background: c.bg, border: `1px solid ${c.border}`, color: c.text,
            padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700, letterSpacing: '1px'
        }}>{normalizedSev}</span>
    );
};

// Operational command view managing raw threat detection data feed allowing administrative curation (Review & Acknowledgment) and rule insight
const ThreatHunter = ({ user }) => {
    const [detections, setDetections] = useState([]);
    const [stats, setStats] = useState({ by_severity: [], last_24h: 0, unacknowledged: 0 });
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expandedRow, setExpandedRow] = useState(null);
    const [filters, setFilters] = useState({ severity: 'ALL', acknowledged: 'ALL', search: '' });
    const [page, setPage] = useState(1);
    const [total, setTotal] = useState(0);
    const LIMIT = 25;

    // Queries detections endpoint mapping parameters and populating dashboard elements including rules, timeline, and table concurrently via Promise.all
    const fetchData = useCallback(async () => {
        try {
            const uid = user?.uid || '';
            const params = new URLSearchParams({ limit: LIMIT, page, requester_uid: uid });
            if (filters.severity !== 'ALL') params.set('severity', filters.severity);
            if (filters.acknowledged !== 'ALL') params.set('acknowledged', filters.acknowledged === 'RESOLVED' ? 'true' : 'false');

            const [detRes, statsRes, rulesRes] = await Promise.all([
                axios.get(`${API}/api/detections?${params}`),
                axios.get(`${API}/api/detections/stats?requester_uid=${uid}`),
                axios.get(`${API}/api/detection-rules?requester_uid=${uid}`),
            ]);
            setDetections(detRes.data.detections || []);
            setTotal(detRes.data.total || 0);
            setStats(statsRes.data);
            setRules(rulesRes.data);
        } catch (e) {
            console.error('[ThreatHunter] fetch error', e);
        } finally {
            setLoading(false);
        }
    }, [filters, page, user?.uid]);

    useEffect(() => { fetchData(); const i = setInterval(fetchData, 15000); return () => clearInterval(i); }, [fetchData]);

    // Issues command closing an anomalous detection indicating human evaluation occurred 
    const acknowledge = async (id) => {
        try {
            const uid = user?.uid || '';
            await axios.patch(`${API}/api/detections/${id}/acknowledge?requester_uid=${uid}`, { acknowledged_by: user?.email || 'ADMIN' });
            fetchData();
        } catch (e) { console.error(e); }
    };

    // Bulk action dispatch clearing backlog of open alerts matching severity filter 
    const acknowledgeAll = async () => {
        try {
            const uid = user?.uid || '';
            await axios.patch(`${API}/api/detections/acknowledge-all?requester_uid=${uid}`, { severity: filters.severity });
            fetchData();
        } catch (e) { console.error(e); }
    };

    const filtered = detections.filter(d =>
        filters.search === '' ||
        d.rule_name?.toLowerCase().includes(filters.search.toLowerCase()) ||
        d.hostname?.toLowerCase().includes(filters.search.toLowerCase()) ||
        d.mitre_id?.toLowerCase().includes(filters.search.toLowerCase())
    );

    const statCards = [
        { label: '24H ALERTS', value: stats.last_24h, color: '#06b6d4' },
        { label: 'UNRESOLVED', value: stats.unacknowledged, color: '#ef4444' },
        { label: 'ACTIVE RULES', value: rules.length, color: '#8b5cf6' },
        { label: 'CRITICAL', value: parseInt((stats.by_severity.find(s => s.severity === 'CRITICAL') || {}).count || 0), color: '#ef4444' },
        { label: 'HIGH', value: parseInt((stats.by_severity.find(s => s.severity === 'HIGH') || {}).count || 0), color: '#f97316' },
        { label: 'MEDIUM', value: parseInt((stats.by_severity.find(s => s.severity === 'MEDIUM') || {}).count || 0), color: '#eab308' },
    ];

    return (
        <div style={{ padding: '24px', height: '100%', overflowY: 'auto', fontFamily: "'Inter', monospace" }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                <div>
                    <h2 style={{ color: '#06b6d4', margin: 0, fontSize: '22px', letterSpacing: '4px', fontWeight: 700 }}>
                        🎯 THREAT HUNTER
                    </h2>
                    <p style={{ color: '#64748b', margin: '4px 0 0', fontSize: '12px' }}>
                        Real-time detection engine — {total} events tracked
                    </p>
                </div>
                <button
                    onClick={acknowledgeAll}
                    style={{ background: 'rgba(100,116,139,0.2)', border: '1px solid #475569', color: '#94a3b8', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}
                >
                    ✓ ACKNOWLEDGE ALL
                </button>
            </div>

            {/* Stat Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '12px', marginBottom: '24px' }}>
                {statCards.map(c => (
                    <div key={c.label} style={{ background: 'rgba(15,23,42,0.8)', border: `1px solid ${c.color}33`, borderRadius: '10px', padding: '16px', textAlign: 'center' }}>
                        <div style={{ fontSize: '28px', fontWeight: 800, color: c.color, lineHeight: 1 }}>{c.value}</div>
                        <div style={{ fontSize: '9px', color: '#64748b', marginTop: '6px', letterSpacing: '1px' }}>{c.label}</div>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
                <input
                    placeholder="🔍 Search rule, host, technique..."
                    value={filters.search}
                    onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
                    style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', color: '#e2e8f0', padding: '8px 14px', borderRadius: '6px', fontSize: '13px', width: '280px', outline: 'none' }}
                />
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                    <button key={s} onClick={() => { setFilters(f => ({ ...f, severity: s })); setPage(1); }}
                        style={{
                            background: filters.severity === s ? (SEV_COLOR[s] || { bg: 'rgba(6,182,212,0.2)' }).bg : 'rgba(15,23,42,0.6)',
                            border: `1px solid ${filters.severity === s ? (SEV_COLOR[s] || { border: '#06b6d4' }).border : '#1e3a5f'}`,
                            color: filters.severity === s ? (SEV_COLOR[s] || { text: '#06b6d4' }).text : '#64748b',
                            padding: '7px 14px', borderRadius: '6px', cursor: 'pointer', fontSize: '11px', fontWeight: 700
                        }}
                    >{s}</button>
                ))}
                <select
                    value={filters.acknowledged}
                    onChange={e => setFilters(f => ({ ...f, acknowledged: e.target.value }))}
                    style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', color: '#94a3b8', padding: '8px', borderRadius: '6px', fontSize: '12px' }}
                >
                    <option value="ALL">All Status</option>
                    <option value="OPEN">Open Only</option>
                    <option value="RESOLVED">Resolved</option>
                </select>
            </div>

            {/* Table */}
            {loading ? (
                <div style={{ textAlign: 'center', padding: '60px', color: '#475569' }}>
                    <div style={{ fontSize: '32px', marginBottom: '12px' }}>⏳</div>
                    Loading detections...
                </div>
            ) : filtered.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '60px', color: '#475569' }}>
                    <div style={{ fontSize: '48px', marginBottom: '12px' }}>🛡️</div>
                    <div style={{ fontSize: '16px' }}>No detections found</div>
                    <div style={{ fontSize: '12px', marginTop: '8px' }}>The system is monitoring for threats</div>
                </div>
            ) : (
                <div style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid #1e3a5f', borderRadius: '12px', overflow: 'hidden' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr style={{ background: 'rgba(6,182,212,0.08)', borderBottom: '1px solid #1e3a5f' }}>
                                {['SEVERITY', 'RULE', 'MITRE ID', 'HOST', 'CONFIDENCE', 'TIMESTAMP', 'STATUS', 'ACTION'].map(h => (
                                    <th key={h} style={{ padding: '12px 14px', textAlign: 'left', fontSize: '10px', color: '#06b6d4', letterSpacing: '2px', fontWeight: 700 }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((d, i) => (
                                <React.Fragment key={d.id}>
                                    <tr
                                        onClick={() => setExpandedRow(expandedRow === d.id ? null : d.id)}
                                        style={{
                                            borderBottom: '1px solid rgba(30,58,95,0.4)',
                                            background: expandedRow === d.id ? 'rgba(6,182,212,0.05)' : i % 2 === 0 ? 'rgba(0,0,0,0.1)' : 'transparent',
                                            cursor: 'pointer',
                                            opacity: d.acknowledged ? 0.5 : 1,
                                            transition: 'background 0.2s'
                                        }}
                                    >
                                        <td style={{ padding: '12px 14px' }}><SeverityBadge sev={d.severity} /></td>
                                        <td style={{ padding: '12px 14px', color: '#e2e8f0', fontSize: '12px', fontWeight: 600, maxWidth: '180px' }}>
                                            {d.rule_name?.replace(/_/g, ' ')}
                                        </td>
                                        <td style={{ padding: '12px 14px' }}>
                                            <span style={{ color: '#8b5cf6', fontSize: '11px', fontFamily: 'monospace', background: 'rgba(139,92,246,0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                                                {d.mitre_id || '—'}
                                            </span>
                                        </td>
                                        <td style={{ padding: '12px 14px', color: '#94a3b8', fontSize: '11px', fontFamily: 'monospace' }}>{d.hostname || '—'}</td>
                                        <td style={{ padding: '12px 14px' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                <div style={{ width: '50px', height: '4px', background: '#1e3a5f', borderRadius: '2px' }}>
                                                    <div style={{ width: `${d.confidence_score || 0}%`, height: '100%', background: d.confidence_score > 80 ? '#22c55e' : d.confidence_score > 60 ? '#eab308' : '#ef4444', borderRadius: '2px' }} />
                                                </div>
                                                <span style={{ color: '#94a3b8', fontSize: '10px' }}>{d.confidence_score || 0}%</span>
                                            </div>
                                        </td>
                                        <td style={{ padding: '12px 14px', color: '#64748b', fontSize: '11px' }}>
                                            {new Date(d.timestamp).toLocaleString()}
                                        </td>
                                        <td style={{ padding: '12px 14px' }}>
                                            {d.acknowledged
                                                ? <span style={{ color: '#22c55e', fontSize: '10px', fontWeight: 700 }}>✓ RESOLVED</span>
                                                : <span style={{ color: '#ef4444', fontSize: '10px', fontWeight: 700 }}>● OPEN</span>
                                            }
                                        </td>
                                        <td style={{ padding: '12px 14px' }} onClick={e => e.stopPropagation()}>
                                            {!d.acknowledged && (
                                                <button onClick={() => acknowledge(d.id)}
                                                    style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid #22c55e', color: '#22c55e', padding: '4px 10px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', fontWeight: 700 }}
                                                >
                                                    ACKNOWLEDGE
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                    {expandedRow === d.id && (
                                        <tr>
                                            <td colSpan={8} style={{ background: 'rgba(6,182,212,0.05)', padding: '0' }}>
                                                <div style={{ padding: '16px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                                                    <div>
                                                        <div style={{ color: '#06b6d4', fontSize: '10px', letterSpacing: '2px', marginBottom: '6px' }}>TRIGGER REASON</div>
                                                        <div style={{ color: '#94a3b8', fontSize: '12px', lineHeight: 1.5 }}>{d.trigger_reason || '—'}</div>
                                                        <div style={{ color: '#06b6d4', fontSize: '10px', letterSpacing: '2px', marginTop: '12px', marginBottom: '6px' }}>MITIGATION</div>
                                                        <div style={{ color: '#94a3b8', fontSize: '12px', lineHeight: 1.5 }}>{d.mitigation || '—'}</div>
                                                    </div>
                                                    <div>
                                                        <div style={{ color: '#06b6d4', fontSize: '10px', letterSpacing: '2px', marginBottom: '6px' }}>EVIDENCE</div>
                                                        <pre style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid #1e3a5f', padding: '10px', borderRadius: '6px', fontSize: '10px', color: '#94a3b8', overflow: 'auto', maxHeight: '100px', margin: 0 }}>
                                                            {JSON.stringify(d.evidence, null, 2)}
                                                        </pre>
                                                        {d.acknowledged && (
                                                            <div style={{ marginTop: '8px', color: '#64748b', fontSize: '11px' }}>
                                                                Resolved by: {d.acknowledged_by} at {d.acknowledged_at ? new Date(d.acknowledged_at).toLocaleString() : '—'}
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Pagination */}
            {total > LIMIT && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '16px' }}>
                    <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
                        style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', color: '#94a3b8', padding: '6px 14px', borderRadius: '6px', cursor: page === 1 ? 'not-allowed' : 'pointer', fontSize: '12px' }}>
                        ← Prev
                    </button>
                    <span style={{ color: '#64748b', padding: '6px 14px', fontSize: '12px' }}>
                        Page {page} of {Math.ceil(total / LIMIT)}
                    </span>
                    <button disabled={page >= Math.ceil(total / LIMIT)} onClick={() => setPage(p => p + 1)}
                        style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', color: '#94a3b8', padding: '6px 14px', borderRadius: '6px', cursor: page >= Math.ceil(total / LIMIT) ? 'not-allowed' : 'pointer', fontSize: '12px' }}>
                        Next →
                    </button>
                </div>
            )}

            {/* Detection Rules Reference */}
            <div style={{ marginTop: '32px' }}>
                <h3 style={{ color: '#8b5cf6', fontSize: '13px', letterSpacing: '3px', marginBottom: '16px' }}>🔧 ACTIVE DETECTION RULES ({rules.length})</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
                    {rules.map(r => (
                        <div key={r.id} style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <div style={{ flex: 1 }}>
                                <div style={{ color: '#e2e8f0', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>{r.rule_name?.replace(/_/g, ' ')}</div>
                                <div style={{ color: '#64748b', fontSize: '10px', lineHeight: 1.4 }}>{r.description}</div>
                                <div style={{ color: '#8b5cf6', fontSize: '10px', marginTop: '6px', fontFamily: 'monospace' }}>{r.mitre_id} • {r.tactic}</div>
                            </div>
                            <div style={{ marginLeft: '12px', textAlign: 'right' }}>
                                <SeverityBadge sev={r.severity} />
                                <div style={{ color: '#64748b', fontSize: '9px', marginTop: '4px' }}>conf: {r.confidence_score}%</div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ThreatHunter;
