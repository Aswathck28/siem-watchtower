import React, { useState, useEffect } from 'react';
import axios from 'axios';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

const API = 'http://localhost:5000';

const SEV_COLOR_MAP = { CRITICAL: [239,68,68], HIGH: [249,115,22], MEDIUM: [234,179,8], LOW: [34,197,94] };

// ===========================================================
// PDF GENERATOR
// ===========================================================
// Constructs and downloads a highly customized formatted PDF document containing structured aggregated intel depending on selected view schema 
const generatePDF = (reportData, reportType, days) => {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const now = new Date();

    // --- HEADER ---
    doc.setFillColor(8, 20, 45);
    doc.rect(0, 0, pageW, 40, 'F');
    doc.setFontSize(22);
    doc.setTextColor(6, 182, 212);
    doc.setFont('helvetica', 'bold');
    doc.text('SIEM WATCHTOWER', 14, 16);
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.text('Enterprise Security Intelligence Platform', 14, 23);
    doc.setFontSize(9);
    doc.text(`Report: ${reportType.toUpperCase()} | Period: Last ${days} days`, 14, 30);
    doc.text(`Generated: ${now.toLocaleString()} | Classification: CONFIDENTIAL`, 14, 36);

    // Right side badge
    doc.setFillColor(6, 182, 212);
    doc.roundedRect(pageW - 50, 8, 36, 12, 2, 2, 'F');
    doc.setFontSize(8);
    doc.setTextColor(8, 20, 45);
    doc.setFont('helvetica', 'bold');
    doc.text('ENTERPRISE SIEM', pageW - 49, 16);

    let yPos = 50;

    if (reportType === 'threat-summary' && reportData) {
        // --- SEVERITY SUMMARY ---
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.setFont('helvetica', 'bold');
        doc.text('1. SEVERITY SUMMARY', 14, yPos);
        yPos += 8;

        const sevData = reportData.severity_summary || [];
        const sevRows = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => {
            const found = sevData.find(r => r.severity === s);
            return [s, found ? found.count : '0'];
        });
        autoTable(doc, {
            startY: yPos, head: [['SEVERITY', 'COUNT']], body: sevRows,
            headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 9 },
            bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 9 },
            alternateRowStyles: { fillColor: [13, 30, 65] },
            didParseCell: (data) => {
                if (data.section === 'body' && data.column.index === 0) {
                    const col = SEV_COLOR_MAP[data.cell.raw] || [148, 163, 184];
                    data.cell.styles.textColor = col;
                    data.cell.styles.fontStyle = 'bold';
                }
            },
            margin: { left: 14, right: 14 }
        });
        yPos = doc.lastAutoTable.finalY + 12;

        // --- TOP ATTACK RULES ---
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.text('2. TOP TRIGGERED ATTACK RULES', 14, yPos);
        yPos += 8;

        const ruleData = (reportData.top_triggered_rules || []).map(r => [
            r.rule_name?.replace(/_/g, ' '), r.mitre_id || '—', r.severity, r.count
        ]);
        if (ruleData.length > 0) {
            autoTable(doc, {
                startY: yPos,
                head: [['RULE NAME', 'MITRE ID', 'SEVERITY', 'COUNT']],
                body: ruleData,
                headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 9 },
                bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 8 },
                alternateRowStyles: { fillColor: [13, 30, 65] },
                margin: { left: 14, right: 14 }
            });
            yPos = doc.lastAutoTable.finalY + 12;
        }

        // --- TOP SUSPICIOUS HOSTS ---
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.text('3. TOP AFFECTED HOSTS', 14, yPos);
        yPos += 8;

        const hostData = (reportData.top_affected_hosts || []).map(h => [h.hostname || '—', h.detections, h.last_seen ? new Date(h.last_seen).toLocaleDateString() : '—']);
        if (hostData.length > 0) {
            autoTable(doc, {
                startY: yPos,
                head: [['HOSTNAME', 'DETECTIONS', 'LAST SEEN']],
                body: hostData,
                headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 9 },
                bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 8 },
                alternateRowStyles: { fillColor: [13, 30, 65] },
                margin: { left: 14, right: 14 }
            });
            yPos = doc.lastAutoTable.finalY + 12;
        }

        // --- TOP RISK ENTITIES ---
        if (reportData.top_risk_entities?.length > 0) {
            doc.setFontSize(13);
            doc.setTextColor(6, 182, 212);
            doc.text('4. TOP RISK ENTITIES', 14, yPos);
            yPos += 8;
            const riskData = reportData.top_risk_entities.map(e => [e.entity_id, e.entity_type, e.score, e.risk_level]);
            autoTable(doc, {
                startY: yPos, head: [['ENTITY', 'TYPE', 'SCORE', 'RISK LEVEL']], body: riskData,
                headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 9 },
                bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 8 },
                alternateRowStyles: { fillColor: [13, 30, 65] },
                margin: { left: 14, right: 14 }
            });
            yPos = doc.lastAutoTable.finalY + 12;
        }

        // --- RECOMMENDATIONS ---
        doc.addPage();
        doc.setFillColor(8, 20, 45);
        doc.rect(0, 0, pageW, 18, 'F');
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.setFont('helvetica', 'bold');
        doc.text('5. RECOMMENDATIONS', 14, 13);
        yPos = 26;

        const recs = [
            ['Enforce MFA', 'Mandatory multi-factor authentication for all user accounts'],
            ['Patch Management', 'Ensure all endpoints are running latest OS and software patches'],
            ['Least Privilege', 'Review and restrict admin privileges to only required accounts'],
            ['USB Policy', 'Implement USB device whitelisting via group policy'],
            ['Network Segmentation', 'Isolate critical assets using VLANs and firewall rules'],
            ['Incident Response Plan', 'Test and update your IR playbook quarterly'],
            ['Log Retention', 'Maintain at minimum 90 days of log retention for forensics'],
            ['PowerShell Hardening', 'Enable Constrained Language Mode and script block logging'],
        ];
        autoTable(doc, {
            startY: yPos, head: [['ACTION ITEM', 'DESCRIPTION']], body: recs,
            headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 9 },
            bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 8 },
            alternateRowStyles: { fillColor: [13, 30, 65] },
            columnStyles: { 0: { fontStyle: 'bold', textColor: [234, 179, 8] } },
            margin: { left: 14, right: 14 }
        });
    }

    if (reportType === 'mitre-coverage' && reportData) {
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.text('MITRE ATT&CK COVERAGE REPORT', 14, yPos);
        yPos += 8;
        const rows = reportData.map(r => [r.matrix_id, r.technique_name, r.tactic, r.detections, r.coverage_status]);
        autoTable(doc, {
            startY: yPos,
            head: [['TECHNIQUE ID', 'NAME', 'TACTIC', 'DETECTIONS', 'COVERAGE']],
            body: rows,
            headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 8 },
            bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 7 },
            alternateRowStyles: { fillColor: [13, 30, 65] },
            didParseCell: (data) => {
                if (data.section === 'body' && data.column.index === 4) {
                    const v = data.cell.raw;
                    if (v === 'DETECTED') data.cell.styles.textColor = [34, 197, 94];
                    else if (v === 'PARTIALLY_DETECTED') data.cell.styles.textColor = [234, 179, 8];
                    else data.cell.styles.textColor = [239, 68, 68];
                }
            },
            margin: { left: 14, right: 14 }
        });
    }

    if (reportType === 'alerts' && reportData) {
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.text('ALERTS REPORT', 14, yPos);
        yPos += 8;
        const rows = reportData.map(r => [r.severity, r.alert_type, r.username || '—', r.mitre_technique_id || '—', new Date(r.timestamp).toLocaleString()]);
        autoTable(doc, {
            startY: yPos,
            head: [['SEVERITY', 'ALERT TYPE', 'USER', 'MITRE', 'TIMESTAMP']],
            body: rows,
            headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 8 },
            bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 7 },
            alternateRowStyles: { fillColor: [13, 30, 65] },
            margin: { left: 14, right: 14 }
        });
    }

    if (reportType === 'user-activity' && reportData) {
        doc.setFontSize(13);
        doc.setTextColor(6, 182, 212);
        doc.text('USER ACTIVITY REPORT', 14, yPos);
        yPos += 8;
        const rows = reportData.map(r => [r.email || '—', r.action_type, r.source_ip || '—', r.mapped_technique_id || '—', new Date(r.timestamp).toLocaleString()]);
        autoTable(doc, {
            startY: yPos,
            head: [['USER', 'ACTION', 'SOURCE IP', 'MITRE', 'TIMESTAMP']],
            body: rows,
            headStyles: { fillColor: [8, 20, 45], textColor: [6, 182, 212], fontStyle: 'bold', fontSize: 8 },
            bodyStyles: { fillColor: [10, 25, 55], textColor: [226, 232, 240], fontSize: 7 },
            alternateRowStyles: { fillColor: [13, 30, 65] },
            margin: { left: 14, right: 14 }
        });
    }

    // --- FOOTER on all pages ---
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFillColor(8, 20, 45);
        doc.rect(0, doc.internal.pageSize.getHeight() - 12, pageW, 12, 'F');
        doc.setFontSize(7);
        doc.setTextColor(100, 116, 139);
        doc.text(`SIEM Watchtower — Confidential Security Report — Page ${i} of ${pageCount}`, pageW / 2, doc.internal.pageSize.getHeight() - 4, { align: 'center' });
    }

    doc.save(`siem_${reportType}_${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}.pdf`);
};

// ===========================================================
// CSV GENERATOR
// ===========================================================
// Translates structured JSON array output directly into raw downloadable CSV blobs natively bypassing backend export needs in browser
const generateCSV = (data, filename) => {
    if (!data || data.length === 0) return;
    const headers = Object.keys(data[0]);
    const rows = data.map(row => headers.map(h => {
        const val = row[h];
        if (val === null || val === undefined) return '';
        const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
        return `"${str.replace(/"/g, '""')}"`;
    }).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
};

// ===========================================================
// REPORTS PAGE COMPONENT
// ===========================================================
// Centralized dedicated reporting interface granting admins the ability to run ad-hoc metrics retrieval and output into tangible document files 
const ReportsPage = () => {
    const [reportType, setReportType] = useState('threat-summary');
    const [days, setDays] = useState(7);
    const [loading, setLoading] = useState(false);
    const [previewData, setPreviewData] = useState(null);
    const [error, setError] = useState('');

    const REPORT_TYPES = [
        { id: 'threat-summary', label: 'Threat Summary', icon: '🎯', description: 'Full threat overview: detections, top attacks, risk entities, recommendations' },
        { id: 'mitre-coverage', label: 'MITRE Coverage', icon: '🗺️', description: 'ATT&CK technique coverage status and gap analysis' },
        { id: 'alerts', label: 'Alert History', icon: '🔔', description: 'All triggered alerts with severity and MITRE mapping' },
        { id: 'user-activity', label: 'User Activity', icon: '👤', description: 'User action logs, source IPs, and technique identifications' },
    ];

    // Dispatches query to explicitly retrieve an abridged dataset used to visually preview report structural formatting and partial contents prior to rendering complete document
    const fetchPreview = async () => {
        setLoading(true); setError('');
        try {
            const user = JSON.parse(localStorage.getItem('user') || '{}');
            const uid = user.uid || '';
            const res = await axios.get(`${API}/api/reports/${reportType}?days=${days}&requester_uid=${uid}`);
            setPreviewData(res.data);
        } catch (e) {
            setError('Failed to fetch report data. Make sure the server is running.');
        } finally { setLoading(false); }
    };

    useEffect(() => {
        fetchPreview();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [reportType, days]);

    // Wrapper catching and resolving report generation logic ensuring accurate status loaders display
    const handlePDF = async () => {
        setLoading(true);
        try {
            const user = JSON.parse(localStorage.getItem('user') || '{}');
            const uid = user.uid || '';
            const res = await axios.get(`${API}/api/reports/${reportType}?days=${days}&requester_uid=${uid}`);
            generatePDF(res.data, reportType, days);
        } catch (e) { setError('PDF generation failed.'); }
        finally { setLoading(false); }
    };

    // Wrapper organizing nested structures (like threat-summaries) safely into flattened readable rows for spreadsheet compatibility 
    const handleCSV = async () => {
        setLoading(true);
        try {
            const res = await axios.get(`${API}/api/reports/${reportType}?days=${days}`);
            let data = res.data;
            // Flatten threat-summary which is nested
            if (reportType === 'threat-summary') data = data.top_triggered_rules || [];
            const dateStr = new Date().toISOString().split('T')[0];
            generateCSV(Array.isArray(data) ? data : [], `siem_${reportType}_${dateStr}.csv`);
        } catch (e) { setError('CSV export failed.'); }
        finally { setLoading(false); }
    };

    // Extrapolates array from potentially deeply nested heterogeneous REST JSON responses returning safe display iterations specifically for React Table mapping
    const previewRows = () => {
        if (!previewData) return [];
        if (Array.isArray(previewData)) return previewData.slice(0, 10);
        if (previewData.top_triggered_rules) return previewData.top_triggered_rules.slice(0, 10);
        return [];
    };

    return (
        <div style={{ padding: '24px', height: '100%', overflowY: 'auto', fontFamily: "'Inter', monospace" }}>
            {/* Header */}
            <div style={{ marginBottom: '28px' }}>
                <h2 style={{ color: '#06b6d4', margin: 0, fontSize: '22px', letterSpacing: '4px', fontWeight: 700 }}>📊 REPORTS & EXPORT</h2>
                <p style={{ color: '#64748b', margin: '4px 0 0', fontSize: '12px' }}>
                    Generate professional PDF reports and CSV exports for audits, viva, and presentations
                </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '24px' }}>
                {/* Left Panel */}
                <div>
                    {/* Report Type */}
                    <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', borderRadius: '12px', padding: '20px', marginBottom: '16px' }}>
                        <div style={{ color: '#06b6d4', fontSize: '11px', letterSpacing: '2px', marginBottom: '14px', fontWeight: 700 }}>SELECT REPORT TYPE</div>
                        {REPORT_TYPES.map(r => (
                            <div key={r.id} onClick={() => setReportType(r.id)}
                                style={{
                                    padding: '12px', borderRadius: '8px', marginBottom: '8px', cursor: 'pointer',
                                    background: reportType === r.id ? 'rgba(6,182,212,0.1)' : 'rgba(0,0,0,0.2)',
                                    border: `1px solid ${reportType === r.id ? '#06b6d4' : '#1e3a5f'}`,
                                    transition: 'all 0.2s'
                                }}
                            >
                                <div style={{ color: reportType === r.id ? '#06b6d4' : '#e2e8f0', fontWeight: 600, fontSize: '13px' }}>
                                    {r.icon} {r.label}
                                </div>
                                <div style={{ color: '#64748b', fontSize: '10px', marginTop: '3px' }}>{r.description}</div>
                            </div>
                        ))}
                    </div>

                    {/* Period */}
                    <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid #1e3a5f', borderRadius: '12px', padding: '20px', marginBottom: '16px' }}>
                        <div style={{ color: '#06b6d4', fontSize: '11px', letterSpacing: '2px', marginBottom: '12px', fontWeight: 700 }}>TIME PERIOD</div>
                        {[7, 14, 30, 90].map(d => (
                            <button key={d} onClick={() => setDays(d)}
                                style={{
                                    background: days === d ? 'rgba(6,182,212,0.2)' : 'rgba(0,0,0,0.2)',
                                    border: `1px solid ${days === d ? '#06b6d4' : '#1e3a5f'}`,
                                    color: days === d ? '#06b6d4' : '#64748b', padding: '8px 14px', borderRadius: '6px',
                                    cursor: 'pointer', marginRight: '8px', marginBottom: '8px', fontSize: '12px', fontWeight: 600
                                }}
                            >Last {d} days</button>
                        ))}
                    </div>

                    {/* Buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <button onClick={fetchPreview} disabled={loading}
                            style={{ background: 'rgba(6,182,212,0.1)', border: '1px solid #06b6d4', color: '#06b6d4', padding: '12px', borderRadius: '8px', cursor: 'pointer', fontWeight: 700, fontSize: '13px' }}>
                            {loading ? '⏳ Loading...' : '👁️ PREVIEW REPORT'}
                        </button>
                        <button onClick={handlePDF} disabled={loading}
                            style={{ background: 'linear-gradient(135deg, #1e3a5f 0%, #0d2748 100%)', border: '1px solid #ef4444', color: '#ef4444', padding: '12px', borderRadius: '8px', cursor: 'pointer', fontWeight: 700, fontSize: '13px' }}>
                            {loading ? '⏳ Generating...' : '📄 DOWNLOAD PDF'}
                        </button>
                        <button onClick={handleCSV} disabled={loading}
                            style={{ background: 'linear-gradient(135deg, #1e3a5f 0%, #0d2748 100%)', border: '1px solid #22c55e', color: '#22c55e', padding: '12px', borderRadius: '8px', cursor: 'pointer', fontWeight: 700, fontSize: '13px' }}>
                            {loading ? '⏳ Exporting...' : '📊 DOWNLOAD CSV'}
                        </button>
                    </div>

                    {error && (
                        <div style={{ marginTop: '12px', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: '8px', padding: '12px', color: '#ef4444', fontSize: '12px' }}>
                            ⚠️ {error}
                        </div>
                    )}
                </div>

                {/* Right Panel: Preview */}
                <div style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid #1e3a5f', borderRadius: '12px', overflow: 'hidden' }}>
                    {/* Mock report preview */}
                    <div style={{ background: 'rgba(8,20,45,0.9)', padding: '20px 24px', borderBottom: '1px solid #1e3a5f' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <div style={{ color: '#06b6d4', fontSize: '18px', fontWeight: 800, letterSpacing: '3px' }}>SIEM WATCHTOWER</div>
                                <div style={{ color: '#64748b', fontSize: '10px' }}>Enterprise Security Intelligence Platform</div>
                                <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '4px' }}>
                                    {REPORT_TYPES.find(r => r.id === reportType)?.label} | Last {days} days | Generated: {new Date().toLocaleString()}
                                </div>
                            </div>
                            <div style={{ background: '#06b6d4', color: '#08142d', padding: '6px 14px', borderRadius: '6px', fontSize: '9px', fontWeight: 800, letterSpacing: '1px' }}>
                                ENTERPRISE SIEM
                            </div>
                        </div>
                    </div>

                    <div style={{ padding: '24px' }}>
                        {!previewData ? (
                            <div style={{ textAlign: 'center', padding: '60px 20px', color: '#475569' }}>
                                <div style={{ fontSize: '48px', marginBottom: '16px' }}>📋</div>
                                <div style={{ fontSize: '16px', marginBottom: '8px' }}>Report Preview</div>
                                <div style={{ fontSize: '12px' }}>Click "Preview Report" to see a summary before downloading</div>
                            </div>
                        ) : (
                            <div>
                                {/* Severity Summary */}
                                {previewData.severity_summary && (
                                    <div style={{ marginBottom: '24px' }}>
                                        <h4 style={{ color: '#06b6d4', fontSize: '12px', letterSpacing: '2px', marginBottom: '12px' }}>SEVERITY DISTRIBUTION</h4>
                                        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                                            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                                                const found = previewData.severity_summary.find(r => r.severity === sev);
                                                const col = SEV_COLOR_MAP[sev] || [148, 163, 184];
                                                const cssColor = `rgb(${col[0]},${col[1]},${col[2]})`;
                                                return (
                                                    <div key={sev} style={{ background: `rgba(${col[0]},${col[1]},${col[2]},0.1)`, border: `1px solid ${cssColor}`, borderRadius: '8px', padding: '12px 20px', textAlign: 'center', minWidth: '80px' }}>
                                                        <div style={{ fontSize: '24px', fontWeight: 800, color: cssColor }}>{found ? found.count : 0}</div>
                                                        <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>{sev}</div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* Data Table Preview */}
                                {previewRows().length > 0 && (
                                    <div>
                                        <h4 style={{ color: '#06b6d4', fontSize: '12px', letterSpacing: '2px', marginBottom: '12px' }}>
                                            DATA PREVIEW (showing first 10 rows)
                                        </h4>
                                        <div style={{ overflowX: 'auto' }}>
                                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                                                <thead>
                                                    <tr style={{ background: 'rgba(6,182,212,0.1)' }}>
                                                        {Object.keys(previewRows()[0] || {}).map(k => (
                                                            <th key={k} style={{ padding: '8px 10px', textAlign: 'left', color: '#06b6d4', fontSize: '9px', letterSpacing: '1px', borderBottom: '1px solid #1e3a5f' }}>
                                                                {k.replace(/_/g, ' ').toUpperCase()}
                                                            </th>
                                                        ))}
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {previewRows().map((row, i) => (
                                                        <tr key={i} style={{ borderBottom: '1px solid rgba(30,58,95,0.4)' }}>
                                                            {Object.values(row).map((v, j) => (
                                                                <td key={j} style={{ padding: '8px 10px', color: '#94a3b8', maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                                    {v === null || v === undefined ? '—' : typeof v === 'object' ? '[object]' : String(v)}
                                                                </td>
                                                            ))}
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}

                                {/* Recommendations section for threat summary */}
                                {reportType === 'threat-summary' && (
                                    <div style={{ marginTop: '24px', background: 'rgba(6,182,212,0.05)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: '8px', padding: '16px' }}>
                                        <h4 style={{ color: '#06b6d4', fontSize: '12px', letterSpacing: '2px', marginBottom: '10px' }}>📌 KEY RECOMMENDATIONS</h4>
                                        {['Enforce MFA on all accounts', 'Apply least-privilege access model', 'Patch endpoints to latest OS version', 'Review USB device access policies', 'Test incident response playbook'].map((rec, i) => (
                                            <div key={i} style={{ color: '#94a3b8', fontSize: '12px', padding: '4px 0', display: 'flex', gap: '8px' }}>
                                                <span style={{ color: '#eab308' }}>→</span> {rec}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReportsPage;
