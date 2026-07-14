import React, { useState, useEffect } from 'react';
import './SimpleDashboard.css';

// ===========================================================
// SIMPLE SOC DASHBOARD COMPONENT
// ===========================================================
// Provides a beginner-friendly aggregated view of system events mapping complexity into digestible easy-to-read grids
function SimpleDashboard() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    // Queries lightweight Node.js intermediary fetching structured simplified logging structures tailored for quick ingestion
    fetch('http://localhost:5000/api/simple-logs')
      .then(res => res.json())
      .then(data => setLogs(data))
      .catch(err => console.error("Error fetching simple logs:", err));
  }, []);

  const filteredLogs = filter === 'ALL' ? logs : logs.filter(log => log.severity === filter);

  // Maps abstract string values indicating alert precedence into tangible hex color styling rules 
  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'HIGH': return { bg: '#fee2e2', text: '#ef4444', border: '#ef4444' };
      case 'MEDIUM': return { bg: '#fef3c7', text: '#f59e0b', border: '#f59e0b'};
      case 'LOW': return { bg: '#d1fae5', text: '#10b981', border: '#10b981' };
      default: return { bg: '#f3f4f6', text: '#6b7280', border: '#6b7280' };
    }
  };

  return (
    <div className="simple-soc-container">
      <header className="simple-soc-header">
        <h1 style={{margin: 0, fontSize: '1.25rem'}}>Mini SOC Dashboard (Demo)</h1>
        
        <div className="simple-filter-group">
          <button onClick={() => setFilter('ALL')} className={filter === 'ALL' ? 'active' : ''}>All Events</button>
          <button onClick={() => setFilter('HIGH')} style={{borderColor: '#ef4444'}} className={filter === 'HIGH' ? 'active-high' : ''}>High</button>
          <button onClick={() => setFilter('MEDIUM')} style={{borderColor: '#f59e0b'}} className={filter === 'MEDIUM' ? 'active-medium' : ''}>Medium</button>
          <button onClick={() => setFilter('LOW')} style={{borderColor: '#10b981'}} className={filter === 'LOW' ? 'active-low' : ''}>Low</button>
        </div>
      </header>

      <table className="simple-logs-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Hostname</th>
            <th>Event Type</th>
            <th>Message</th>
            <th>Occurrence</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {filteredLogs.map(log => {
            const styles = getSeverityStyle(log.severity);
            
            return (
              <tr 
                key={log.id} 
                className="simple-log-row"
                style={{ backgroundColor: log.severity === 'HIGH' ? '#fff0f0' : '#ffffff' }}
              >
                <td className="simple-time-cell">{new Date(log.timestamp).toLocaleTimeString()}</td>
                <td className="simple-host-cell">{log.hostname}</td>
                <td className="simple-type-cell">{log.type}</td>
                <td>{log.message}</td>
                <td>
                  {log.count > 1 ? (
                    <span className="simple-count-badge">{log.count} times</span>
                  ) : <span style={{color: '#9ca3af'}}>Once</span>}
                </td>
                <td>
                  <span className="simple-severity-badge" style={{ backgroundColor: styles.text }}>
                    {log.severity}
                  </span>
                </td>
              </tr>
            );
          })}
          
          {filteredLogs.length === 0 && (
            <tr>
              <td colSpan="6" className="simple-empty-state">No logs found.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default SimpleDashboard;
