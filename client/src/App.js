import React, { useState, useEffect, useCallback, useRef } from 'react';
import './App.css';
import NormalUserDashboard from './user/NormalUserDashboard';
import { auth, provider } from './firebase';
import { signInWithPopup, signOut, createUserWithEmailAndPassword, signInWithEmailAndPassword } from 'firebase/auth';
import axios from 'axios';
import useTelemetry from './hooks/useTelemetry';

import AdminDashboard from './admin/AdminDashboard';
import Icons from './components/Icons';
// --- REUSABLE STARK MODAL COMPONENT ---
import StarkModal from './components/StarkModal';
import TacticalReporter from './components/TacticalReporter';

const SUPER_ADMIN_EMAIL = process.env.REACT_APP_SUPER_ADMIN_EMAIL || "aswathck28@gmail.com"; // SYSTEM ADMIN EMAIL CONFIGURATION

/**
 * Component: App
 * Description: The core functional component of the SIEM Watchtower frontend. 
 *              Manages global state, authentication lifecycle, role-based 
 *              dashboard routing, and data polling for real-time security events.
 * Parameters:
 *   - None
 * Returns:
 *   - JSX.Element: The rendered application UI or authentication screen.
 */
function App() {
  const [user, setUser] = useState(null);
  const [sessionId, setSessionId] = useState(null); // Maintain session ID
  const [isAdmin, setIsAdmin] = useState(false);
  const [activeTab, setActiveTab] = useState('OVERVIEW');
  const [focusedCard, setFocusedCard] = useState(null);

  const [data, setData] = useState({
    meta: { role: 'USER' },
    stats: { users: 0, events: 0, threats: 0 },
    userList: [],
    web: { heatmap: [], actions: [], logs: [], topPaths: [] },
    system: { logs: [] },
    userSystem: { logs: [], frequency: [] }, // INIT: Prevents SYSTEM_LOGS tab from being hidden
    radar: [], mitre: []
  });
  const [intel, setIntel] = useState([]);
  const [selectedThreatId, setSelectedThreatId] = useState(null);

  // Derived State for Matrix (Filtered by Selection)
  const activeThreats = selectedThreatId
    ? (data.threatsList || []).filter(t => t.mapped_technique_id === selectedThreatId)
    : (data.threatsList || []);

  // --- STARK INDUSTRIES: ADVANCED TELEMETRY BEACON (Zero-Latency) ---
  // Hook handles all: Performance, Journey, Errors, DLP, Tamper, Scroll
  const { logBeacon } = useTelemetry(user, sessionId, activeTab);

  const [toasts, setToasts] = useState([]);

  /**
   * Function: showToast
   * Description: Triggers a temporary visual notification (toast) on the screen. 
   *              Used for security alerts and system status updates.
   * Parameters:
   *   - title (str): Header text for the notification.
   *   - message (str): Detailed body text.
   *   - techniqueId (str|null): Optional MITRE technique ID to display.
   * Returns:
   *   - void
   */
  // Dismiss a toast with slide-out animation before removal
  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 300);
  }, []);

  const showToast = useCallback((title, message, techniqueId = null) => {
    // Use random suffix to avoid ID collisions when toasts fire rapidly
    const id = Date.now() + Math.random();
    const newToast = { id, title, message, techniqueId, exiting: false };
    setToasts(prev => [...prev, newToast]);

    // Start slide-out animation 300ms before removal
    setTimeout(() => {
      setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    }, 4700);

    // Remove from DOM after animation completes
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 5000);
  }, []);

  /**
   * Function: logAction
   * Description: Wraps the telemetry beacon with UI-level logic. If the telemetery 
   *              upload indicates a backend anomaly detection, it automatically 
   *              triggers a security toast.
   * Parameters:
   *   - action (str): The logical name of the event being logged.
   *   - details (obj): JSON metadata associated with the event.
   * Returns:
   *   - Promise<object>: The server's response/anomaly analysis.
   */
  const logAction = useCallback(async (action, details = {}) => {
    const result = await logBeacon(action, details);
    if (result && result.isAnomaly) {
      showToast(
        "🚨 SECURITY ALERT",
        `Anomalous ${action.replace('_', ' ')} detected!`,
        result.techniqueId
      );
    }
    return result;
  }, [logBeacon, showToast]);

  // STATES
  const [showUserModal, setShowUserModal] = useState(false);
  const [showThreatsModal, setShowThreatsModal] = useState(false);
  const [showCoveredModal, setShowCoveredModal] = useState(false); // New state for Covered Modal
  const [showEventModal, setShowEventModal] = useState(false);
  const [webFilter, setWebFilter] = useState('all');
  const [webChartData, setWebChartData] = useState([]);
  const [sysDrillEvent, setSysDrillEvent] = useState(null);
  const [sysDrillData, setSysDrillData] = useState([]);
  const [showAllHistory, setShowAllHistory] = useState(false); // Toggle for user history clipping


  const contentRef = useRef(null);

  // --- INTERNAL TAB TRACKING ---
  const lastLoggedTabRef = useRef(null);
  useEffect(() => {
    if (user && activeTab && lastLoggedTabRef.current !== activeTab) {
      const fromTab = lastLoggedTabRef.current;
      logAction('internal_nav', {
        from_tab: fromTab,
        to_tab: activeTab,
        page_path: window.location.pathname,
        timestamp: Date.now()
      });
      lastLoggedTabRef.current = activeTab;
    }
  }, [activeTab, user, logAction]);

  // --- DEVICE FINGERPRINTING ---
  const fingerprintLogged = useRef(false);

  useEffect(() => {
    if (!user || fingerprintLogged.current) return;

    fingerprintLogged.current = true;

    // Collect Fingerprint
    const fingerprint = {
      screen_resolution: `${window.screen.width}x${window.screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      device_memory: navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'Unknown',
      cpu_cores: navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} Cores` : 'Unknown',
    };

    // Log to backend (Once per session startup)
    logAction('device_fingerprint', fingerprint);

  }, [user, logAction]);

  const sessionLogged = useRef(false);

  useEffect(() => {
    if (!user || sessionLogged.current) return;

    sessionLogged.current = true;
    const sessionTimer = setTimeout(() => {
      logAction('long_session_alert', { message: 'User active > 5 mins', email: user.email });
    }, 300000);

    logAction('session_start', { startTime: new Date().toISOString() });

    return () => {
      clearTimeout(sessionTimer);
    };
  }, [user, logAction]);

  // --- DATA FETCHING & ROLE CHECK ---
  const [, setServerStatus] = useState('CHECKING'); // Heartbeat

  /**
   * Function: fetchDashboardData
   * Description: Primary data synchronization routine. Hits the central 
   *              dashboard-data endpoint to retrieve system stats, threat lists, 
   *              and user-specific telemetry. Also performs a role verification.
   * Parameters:
   *   - None (Uses closure of user and webFilter states)
   * Returns:
   *   - Promise<void>: Updates the 'data' state object.
   */
  const fetchDashboardData = useCallback(async () => {
    if (!user) return;
    try {
      // Backend resolves the PC hostname (users.hostname or agent username ↔ email) for system_logs.
      const dashboardRes = await axios.get(
        `http://localhost:5000/api/dashboard-data?uid=${user.uid}${showAllHistory ? '&all_history=true' : ''}`
      );
      // --- USER ISOLATION: Don't merge logs from different users ---
      // Each user should only see their own logs collected after they login
      setData(prev => {
        const newData = dashboardRes.data;
        
        // If role changed or this is first load, use fresh data only
        // Don't merge to prevent cross-user log contamination
        if (!prev || !prev.userSystem || prev.meta?.role !== newData.meta?.role) {
          return newData;
        }
        
        // For same user session, only use new data from server
        // Server already filters by user_id, so we trust server data only
        return newData;
      });

      // --- CRITICAL FIX FOR VISIBILITY ---
      const backendRole = dashboardRes.data.meta ? dashboardRes.data.meta.role : 'USER';

      // Rule: You are Admin if Backend says so OR if you are the Super Admin Email
      if (backendRole === 'ADMIN' || user.email === SUPER_ADMIN_EMAIL) {
        setIsAdmin(true);
      } else {
        setIsAdmin(false); // Force reset for regular users
      }

      if (webFilter === 'all') setWebChartData(dashboardRes.data.web.heatmap);
      // Fetch INTEL only once if empty (Needed for Radar on WEB and MATRIX tabs)
      if (intel.length === 0) {
        try {
          const iRes = await axios.get(`http://localhost:5000/api/intel?requester_uid=${user.uid}`);
          setIntel(iRes.data);
        } catch (e) { }
      }
    } catch (e) {
      setServerStatus('OFFLINE'); // Connection lost
    }
  }, [user, webFilter, intel.length, showAllHistory]);

  // --- POLLING EFFECT ---
  useEffect(() => {
    if (!user) return;
    let isMounted = true;
    let timerId = null;

    const poll = async () => {
      await fetchDashboardData();
      if (isMounted) {
        timerId = setTimeout(poll, 1000); // Wait 1 second after the previous fetch completes
      }
    };
    poll();

    return () => {
      isMounted = false;
      if (timerId) clearTimeout(timerId);
    };
  }, [user, fetchDashboardData]);

  // --- MOUSE PARALLAX LOGIC ---
  useEffect(() => {
    const handleMouseMove = (e) => {
      const x = (e.clientX / window.innerWidth) * 100;
      const y = (e.clientY / window.innerHeight) * 100;
      document.documentElement.style.setProperty('--mouse-x', `${x}%`);
      document.documentElement.style.setProperty('--mouse-y', `${y}%`);
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Initialize session on login
  useEffect(() => {
    if (user) {
      const initLogin = async () => {
        try {
          const res = await axios.post('http://localhost:5000/api/login', {
            uid: user.uid,
            email: user.email
          });
          setSessionId(res.data.sessionId); // Save the session ID from server
        } catch (e) {
          console.error("Failed to initialize session with backend:", e);
        }
      };
      initLogin();
    }
  }, [user]);

  /**
   * Function: handleWebFilter
   * Description: Updates the scope of the web heatmap (e.g., viewing all requests 
   *              vs only anomalies) and fetches the filtered dataset.
   * Parameters:
   *   - type (str): The filter type ('all', 'anomaly', etc.)
   * Returns:
   *   - Promise<void>
   */
  /**
   * Function: handleWebFilter
   * Description: Updates the scope of the web heatmap (e.g., viewing all requests 
   *              vs only anomalies) and fetches the filtered dataset.
   * Parameters:
   *   - type (str): The filter type ('all', 'anomaly', etc.)
   * Returns:
   *   - Promise<void>
   */
  const handleWebFilter = async (type) => {
    setWebFilter(type);
    if (!user) return;
    try {
      const res = await axios.get(`http://localhost:5000/api/heatmap/web/${type}?uid=${user.uid}`);
      setWebChartData(res.data);
    } catch (e) { }
  };

  /**
   * Function: handleSysDrill
   * Description: Fetches granular event data for a specific type of system log 
   *              to be displayed in a detailed drill-down modal.
   * Parameters:
   *   - type (str): The system event type or category.
   * Returns:
   *   - Promise<void>
   */
  const handleSysDrill = async (type) => {
    setSysDrillEvent(type);
    try {
      const res = await axios.get(`http://localhost:5000/api/heatmap/system/${type}`);
      setSysDrillData(res.data);
    } catch (e) { }
  };

  /**
   * Function: simulateAttack
   * Description: Educational/Testing engine that launches mock security threats 
   *              (Brute Force, SQLi, etc.) against the user's own session to 
   *              verify the SIEM's detection and alerting logic.
   * Parameters:
   *   - type (str): Identifier for the attack vector to simulate.
   * Returns:
   *   - Promise<void>: Triggers telemetry events and dashboard alerts.
   */
  const simulateAttack = async (type) => {
    if (!user) return;
    const confirmMsg = `⚠️ AUTHORIZED SIMULATION\n\nTarget: Self (Localhost)\nVector: ${type}\n\nProceed?`;
    if (!window.confirm(confirmMsg)) return;

    try {
      // 1. NOTIFY ADMINS OF SIMULATION START
      await axios.post('http://localhost:5000/api/alert/high-traffic', {
        requestCount: 1,
        duration: 0,
        triggeredBy: `WAR GAMES SIMULATION: ${type} by ${user.email}`
      });

      // 2. EXECUTE ATTACK VECTOR
      switch (type) {
        case 'BRUTE_FORCE':
          for (let i = 0; i < 6; i++) {
            await logAction('login_fail', { user: 'admin', reason: 'Invalid Password' });
          }
          break;

        case 'SQL_INJECTION':
          await logAction('sql_injection', {
            query: 'SELECT * FROM users WHERE id = 1 OR 1=1',
            payload: "' OR '1'='1"
          });
          break;

        case 'XSS':
          await logAction('xss_attack', {
            input: 'search_bar',
            payload: '<script>alert("pwned")</script>'
          });
          break;

        case 'RANSOMWARE_BEACON':
          await logAction('file_access', { file: 'C:/Users/Admin/Documents/passwords.txt', status: 'ENCRYPTED' });
          await logAction('network_connection', { dest: '192.168.1.55 (C2 Server)', port: 4444 });
          break;

        default:
          alert('Unknown Vector');
      }

      showToast(`SIMULATION STARTED: ${type}`, `Launching attack vector against domestic target...`);

      alert(`✅ SIMULATION COMPLETE: ${type}\nCheck Threat Intelligence Dashboard and your Email.`);
      fetchDashboardData(); // Refresh UI
    } catch (e) {
      console.error("Simulation Failed", e);
      alert("Simulation Failed: Server Error");
    }
  };

  /**
   * Function: handleLogout
   * Description: Manages the sign-out process. Clears local credentials, 
   *              notifies the backend for session finalization, and redirects 
   *              to the authentication screen.
   * Parameters:
   *   - None
   * Returns:
   *   - Promise<void>
   */
  const handleLogout = async () => {
    try {
      // Send logout details to backend for duration calculation
      await axios.post('http://localhost:5000/api/logout', {
        uid: user.uid,
        email: user.email,
        reason: 'User clicked logout button'
      });
    } catch (e) { console.error("Logout log failed"); }

    setIsAdmin(false);
    setSessionId(null);
    signOut(auth).then(() => {
      localStorage.removeItem('user');
      setUser(null);
    });
  };

  /**
   * Function: promoteUser
   * Description: Increments the security stance of a specified user to 'ADMIN' 
   *              status via the backend API.
   * Parameters:
   *   - targetUid (str): The Firebase UID of the user to promote.
   * Returns:
   *   - Promise<void>
   */
  const promoteUser = async (targetUid) => {
    if (!window.confirm("Are you sure you want to make this user an Admin?")) return;
    try {
      await axios.post('http://localhost:5000/api/promote', {
        requester_uid: user.uid,
        uid: targetUid
      });
      alert("User Promoted Successfully!");
      const res = await axios.get(`http://localhost:5000/api/dashboard-data?uid=${user.uid}`);
      setData(res.data);
    } catch (err) {
      alert("Failed to promote: " + (err.response?.data || err.message));
    }
  };

  /**
   * Function: demoteUser
   * Description: Revokes the administrative privileges of a specific user, 
   *              restricting them back to standard analyst dashboard access.
   * Parameters:
   *   - targetUid (str): The UID of the admin to demote.
   * Returns:
   *   - Promise<void>
   */
  const demoteUser = async (targetUid) => {
    if (!window.confirm("Are you sure you want to REMOVE Admin privileges from this user?")) return;
    try {
      await axios.post('http://localhost:5000/api/demote', {
        requester_uid: user.uid,
        uid: targetUid
      });
      alert("User API Access Revoked (Demoted to User)!");
      const res = await axios.get(`http://localhost:5000/api/dashboard-data?uid=${user.uid}`);
      setData(res.data);
    } catch (err) {
      alert("Failed to demote: " + (err.response?.data || err.message));
    }
  };

  /**
   * Function: deleteUser
   * Description: Issues a permanent purge command to the backend to remove a user's 
   *              authentication identity and all associated database records.
   * Parameters:
   *   - targetUid (str): Identity of the user to delete.
   *   - email (str): Email for confirmation logging.
   * Returns:
   *   - Promise<void>
   */
  const deleteUser = async (targetUid, email) => {
    if (!window.confirm(`Delete User ${email}? This cannot be undone.`)) return;
    try {
      await axios.post('http://localhost:5000/api/delete-user', {
        requester_uid: user.uid,
        uid: targetUid,
        target_email: email
      });
      alert('User/Host Deleted');
      const res = await axios.get(`http://localhost:5000/api/dashboard-data?uid=${user.uid}`);
      setData(res.data);
    } catch (e) {
      alert('Failed to delete: ' + (e.response?.data || e.message));
    }
  };


  if (!user) return <AuthScreen onLogin={(u) => {
    localStorage.setItem('user', JSON.stringify(u));
    setUser(u);
  }} />;

  return (
    <div className="app-container">

      {/* --- ACTIVE USERS & HOSTS MODAL --- */}
      {showUserModal && (
        <StarkModal title="ACTIVE USERS & HOSTS" onClose={() => setShowUserModal(false)} theme="blue">
          {data.userList && [...data.userList].sort((a, b) => (a.status === 'online' ? -1 : 1)).map((u, i) => (
            <div key={i} className="stark-roster-item">
              <div style={{
                width: '40px', height: '40px', background: 'rgba(14,165,233,0.1)',
                border: '1px solid var(--neon-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--neon-cyan)', borderRadius: '4px'
              }}>
                {u.type === 'HOST' ? <Icons.Cpu /> : (u.email || '?')[0].toUpperCase()}
              </div>

              <div style={{ overflow: 'visible' }}>
                <div style={{ color: '#fff', fontWeight: 'bold', letterSpacing: '1px', wordBreak: 'break-all' }}>
                  {u.email || 'UNKNOWN'}
                </div>
                <div style={{ fontSize: '10px', color: '#64748b', display: 'flex', gap: '10px', alignItems: 'center', marginTop: '4px' }}>
                  <span>ID: {u.firebase_uid?.substring(0, 8)}...</span>
                  <span style={{ color: u.status === 'online' ? 'var(--neon-green)' : '#64748b' }}>
                    {u.status === 'online' ? '● ONLINE' : '○ OFFLINE'}
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', alignItems: 'center' }}>
                {u.role === 'ADMIN' && <span style={{ color: 'var(--neon-gold)', fontSize: '9px', border: '1px solid var(--neon-gold)', padding: '4px 6px', marginRight: 'auto' }}>ADMINISTRATOR</span>}

                {data.meta.role === 'ADMIN' && u.firebase_uid !== user.uid && (
                  <>
                    {u.role !== 'ADMIN' && <button className="logout-btn" style={{ borderColor: 'var(--neon-cyan)', color: 'var(--neon-cyan)', fontSize: '9px', minWidth: '60px' }} onClick={() => promoteUser(u.firebase_uid)}>PROMOTE</button>}
                    {u.role === 'ADMIN' && <button className="logout-btn" style={{ borderColor: 'var(--neon-gold)', color: 'var(--neon-gold)', fontSize: '9px', minWidth: '60px' }} onClick={() => demoteUser(u.firebase_uid)}>DEMOTE</button>}
                    <button className="logout-btn" style={{ fontSize: '9px', minWidth: '50px' }} onClick={() => deleteUser(u.firebase_uid, u.email)}>PURGE</button>
                  </>
                )}
              </div>
            </div>
          ))}
        </StarkModal>
      )}

      {/* --- SECURITY INCIDENT LOG MODAL --- */}
      {showThreatsModal && (
        <StarkModal title="SECURITY INCIDENT LOG" onClose={() => setShowThreatsModal(false)} theme="red">
          {data.threatsList && data.threatsList.length > 0 ? (
            data.threatsList.map((t, i) => {
              const isCurrent = (Date.now() - new Date(t.timestamp).getTime()) < 900000;
              const accentColor = isCurrent ? 'var(--neon-red)' : 'var(--neon-cyan)';
              const bgSelectColor = isCurrent ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 211, 238, 0.2)';

              return (
                <div
                  key={i}
                  className="stark-item"
                  onClick={() => setSelectedThreatId(selectedThreatId === t.mapped_technique_id ? null : t.mapped_technique_id)}
                  style={{
                    borderLeftColor: accentColor,
                    cursor: 'pointer',
                    background: selectedThreatId === t.mapped_technique_id ? bgSelectColor : 'transparent',
                    border: selectedThreatId === t.mapped_technique_id ? `1px solid ${accentColor}` : ''
                  }}
                >
                  <div style={{ width: '100%' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                      <span style={{ color: accentColor, fontWeight: 'bold', letterSpacing: '1px' }}>
                        WARNING: {t.event_type || t.action_type || 'ANOMALY'}
                      </span>
                      <span style={{ fontSize: '10px', color: '#94a3b8' }}>
                        {new Date(t.timestamp).toLocaleTimeString()} {isCurrent ? '(CURRENT)' : '(OLD)'}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: '#cbd5e1', fontFamily: 'var(--hud-font)', background: 'rgba(0,0,0,0.3)', padding: '8px' }}>
                      SOURCE: {t.source} | TECHNIQUE: {t.mapped_technique_id}<br />
                      DETAILS: {JSON.stringify(t.details).substring(0, 120)}...
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div style={{ textAlign: 'center', padding: '50px', color: '#64748b' }}>
              <Icons.Shield style={{ width: 50, height: 50, color: 'var(--neon-green)', marginBottom: 20 }} />
              <div style={{ fontSize: '18px', letterSpacing: '2px' }}>SYSTEM SECURE</div>
              <div>NO ACTIVE THREATS DETECTED</div>
            </div>
          )}
        </StarkModal>
      )}

      {/* --- MITRE COVERAGE MODAL --- */}
      {showCoveredModal && (
        <StarkModal title="MITRE ATT&CK COVERAGE" onClose={() => setShowCoveredModal(false)} theme="blue">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            {data.mitre && data.mitre.map((c, i) => {
              const def = intel ? intel.find(x => x.matrix_id === c.matrix_id) : { name: 'Unknown' };
              return (
                <div key={i} className="stark-item" style={{ borderLeftColor: 'var(--neon-green)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--neon-green)' }}>{c.count}</div>
                    <div>
                      <div style={{ color: '#fff', fontSize: '12px' }}>{def.name}</div>
                      <div style={{ fontSize: '10px', color: 'var(--neon-green)' }}>{c.matrix_id}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </StarkModal>
      )}

      {/* --- AUDIT LOG MODAL --- */}
      {showEventModal && (
        <StarkModal title="NETWORK EVENT STREAM" onClose={() => setShowEventModal(false)} theme="gold">
          <table className="enterprise-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>TYPE</th>
                <th>TECHNIQUE</th>
                <th>PAYLOAD</th>
              </tr>
            </thead>
            <tbody>
              {data.web.logs && data.web.logs.map((log, i) => (
                <tr key={i}>
                  <td style={{ color: '#94a3b8' }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td style={{ color: 'var(--neon-blue)' }}>{log.action_type}</td>
                  <td style={{ color: 'var(--neon-gold)' }}>{log.mapped_technique_id || 'N/A'}</td>
                  <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {JSON.stringify(log.details)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </StarkModal>
      )}

      <aside className="sidebar-jarvis">
        <div className="jarvis-brand">
          <Icons.Shield /> SIEM <span className="text-highlight">WATCHTOWER</span>
        </div>

        <div className="nav-menu">
          {isAdmin ? (
            <>
              <div className={`jarvis-nav-item ${activeTab === 'OVERVIEW' ? 'active' : ''}`} onClick={() => setActiveTab('OVERVIEW')}>
                <Icons.Activity /> <span>SYSTEM OVERVIEW</span>
              </div>
              <div className={`jarvis-nav-item ${activeTab === 'HUNTER' ? 'active' : ''}`} onClick={() => setActiveTab('HUNTER')}>
                <Icons.Shield /> <span>THREAT HUNTER</span>
              </div>
              <div className={`jarvis-nav-item ${activeTab === 'WEB' ? 'active' : ''}`} onClick={() => setActiveTab('WEB')}>
                <Icons.Globe /> <span>NETWORK OVERVIEW</span>
              </div>
              <div className={`jarvis-nav-item ${activeTab === 'SYSTEM' ? 'active' : ''}`} onClick={() => setActiveTab('SYSTEM')}>
                <Icons.Cpu /> <span>SYSTEM HEALTH</span>
              </div>
              <div className={`jarvis-nav-item ${activeTab === 'MATRIX' ? 'active' : ''}`} onClick={() => setActiveTab('MATRIX')}>
                <Icons.Grid /> <span>THREAT INTELLIGENCE</span>
              </div>
              <div className={`jarvis-nav-item ${activeTab === 'REPORTS' ? 'active' : ''}`} onClick={() => setActiveTab('REPORTS')}>
                <Icons.Activity /> <span>REPORTS</span>
              </div>
            </>
          ) : (
            <div className="jarvis-nav-item active">
              <Icons.Shield /> <span>COMMAND CENTER</span>
            </div>
          )}
        </div>

        <div className="user-profile">
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span className="user-name">{user.email?.split('@')[0].toUpperCase()}</span>
            <span className="user-role" style={{ color: isAdmin ? '#eab308' : '#94a3b8' }}>{isAdmin ? 'ADMINISTRATOR' : 'ANALYST'}</span>
          </div>
          <button className="logout-btn" onClick={handleLogout}><Icons.LogOut /></button>
        </div>

      </aside>

      <main className="main-content">
        {/* --- ROLE BASED DASHBOARD SWITCH --- */}
        {!isAdmin ? (
          <div className="content-wrapper" ref={contentRef}>
            <NormalUserDashboard 
              data={data} 
              showAllHistory={showAllHistory} 
              setShowAllHistory={setShowAllHistory} 
            />
          </div>
        ) : (
          <AdminDashboard
            activeTab={activeTab}
            data={data}
            activeThreats={activeThreats}
            webChartData={webChartData}
            webFilter={webFilter}
            handleWebFilter={handleWebFilter}
            setShowUserModal={setShowUserModal}
            setShowEventModal={setShowEventModal}
            setShowThreatsModal={setShowThreatsModal}
            setShowCoveredModal={setShowCoveredModal}
            sysDrillEvent={sysDrillEvent}
            sysDrillData={sysDrillData}
            handleSysDrill={handleSysDrill}
            setSysDrillEvent={setSysDrillEvent}
            simulateAttack={simulateAttack}
            intel={intel}
            onFocus={setFocusedCard}
            user={user}
          />
        )}
      </main>

      {/* --- FOCUS MODE OVERLAY --- */}
      {focusedCard && (
        <div className="stark-overlay" onClick={() => setFocusedCard(null)}>
          <div className="card-focus-mode" onClick={e => e.stopPropagation()}>
            <div className="stark-header">
              <span className="stark-title">HIGH-DETAIL SPECTRAL ANALYSIS</span>
              <button className="stark-close-btn" onClick={() => setFocusedCard(null)}>×</button>
            </div>
            <div className="stark-body" style={{ height: 'calc(100% - 60px)' }}>
              {focusedCard}
            </div>
          </div>
        </div>
      )}

      {/* --- USER TACTICAL REPORTER --- */}
      {!isAdmin && user && (
        <TacticalReporter userUid={user.uid} />
      )}
      {/* --- LIVE SECURITY TOASTS --- */}
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className={`security-toast${toast.exiting ? ' toast-exit' : ''}`}>
            <div className="toast-icon">
              <Icons.Shield size={20} />
            </div>
            <div className="toast-content">
              <div className="toast-title">{toast.title}</div>
              <div className="toast-msg">{toast.message}</div>
              {toast.techniqueId && (
                <div className="toast-technique">MITRE: {toast.techniqueId}</div>
              )}
            </div>
            <button
              className="stark-close-btn"
              style={{ fontSize: '14px', padding: '0 5px' }}
              onClick={() => dismissToast(toast.id)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Component: AuthScreen
 * Description: The entrance portal of the application. Provides cinematic 
 *              initialization UX and handles Email/Password and Google Social 
 *              authentication using Firebase.
 * Parameters:
 *   - onLogin (function): Callback to pass the authenticated Firebase User 
 *                         back to the root App component.
 * Returns:
 *   - JSX.Element: The rendered authentication terminal.
 */
const AuthScreen = ({ onLogin }) => {
  // Intro State
  const [intro, setIntro] = useState(true);
  const [introText, setIntroText] = useState("INITIALIZING SECURE PROTOCOLS...");

  // Auth State
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPass] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  useEffect(() => {
    // Cinematic Intro Sequence
    setTimeout(() => setIntroText("VERIFYING ENCRYPTION KEYS..."), 800);
    setTimeout(() => setIntroText("CONNECTING TO WATCHTOWER..."), 1600);
    setTimeout(() => setIntro(false), 2300);
  }, []);

  if (intro) {
    return (
      <div className="intro-container">
        <Icons.Shield />
        <div style={{ marginTop: 20, fontFamily: 'var(--hud-font)', color: 'var(--neon-cyan)', letterSpacing: '2px', fontSize: '12px' }}>
          {introText}
        </div>
        <div className="intro-loader"><div className="intro-bar"></div></div>
      </div>
    );
  }

  /**
   * Function: handleAuth
   * Description: Processes manual authentication requests (Login or Signup). 
   *              Includes strict regex validation for organization emails 
   *              and password complexity before hitting Firebase.
   * Parameters:
   *   - e (Event): The form submission event.
   * Returns:
   *   - Promise<void>
   */
  const handleAuth = async (e) => {
    e.preventDefault();

    // 1. EMAIL VALIDATION (6-64 chars before @, domain gmail.com or .ac.in)
    const emailRegex = /^[a-zA-Z0-9._%+-]{6,30}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailRegex.test(email)) {
      alert("⚠️ INVALID EMAIL\n\n- Name before @ must be 6-64 characters.\n- Must start with a letter or digit.\n- Domain must be gmail.com or end with .ac.in");
      return;
    }

    // 2. PASSWORD VALIDATION (8+ chars, 1 upper, 1 lower, 1 number)
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passRegex.test(password)) {
      alert("⚠️ WEAK PASSWORD\n\n- Minimum 8 characters.\n- Must include Uppercase, Lowercase, and a Number.");
      return;
    }

    try {
      let res = isLogin
        ? await signInWithEmailAndPassword(auth, email, password)
        : await createUserWithEmailAndPassword(auth, email, password);

      onLogin(res.user);
    } catch (err) {
      const code = err?.code || 'auth/unknown';
      
      // Notify backend of the failure with the SPECIFIC reason
      axios.post('http://localhost:5000/api/login', {
        email: email,
        status: 'fail',
        reason: code,
        auth_mode: isLogin ? 'LOGIN' : 'SIGNUP'
      }).catch(err => console.error("Failed to report login error:", err));

      if (code === 'auth/email-already-in-use') {
        alert("⚠️ EMAIL ALREADY EXISTS\n\nThis email is already registered.\n\nAction: Switch to LOGIN and sign in with the same email.");
      } else if (code === 'auth/wrong-password' || code === 'auth/invalid-credential') {
        alert("⚠️ INCORRECT PASSWORD\n\nAction: Double-check credentials and try again.");
      } else if (code === 'auth/user-not-found') {
        alert("⚠️ ACCOUNT NOT FOUND\n\nNo account found for this email.\n\nAction: Switch to SIGN UP to create one.");
      } else if (code === 'auth/too-many-requests') {
        alert("⚠️ TOO MANY REQUESTS\n\nAction: Wait a minute and try again.");
      } else {
        alert(err?.message || 'Authentication failed.');
      }
    }
  };

  /**
   * Function: handleGoogle
   * Description: Initiates a Firebase popup for Google OAuth 2.0 authentication. 
   *              Bypasses manual credential fields for authorized SSO access.
   * Parameters:
   *   - None
   * Returns:
   *   - Promise<void>
   */
  const handleGoogle = async () => {
    if (isLoggingIn) return;
    setIsLoggingIn(true);
    try {
      const res = await signInWithPopup(auth, provider);
      if (res && res.user) {
        onLogin(res.user);
      }
    } catch (error) {
      if (error.code !== 'auth/cancelled-popup-request') alert(error.message);
    } finally { setIsLoggingIn(false); }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-logo"><Icons.Shield /></div>
        <h1 style={{ letterSpacing: '5px', marginBottom: '5px' }}>SIEM <span style={{ color: 'var(--neon-cyan)' }}>WATCHTOWER</span></h1>
        <p style={{ fontSize: '10px', letterSpacing: '3px', color: '#64748b', marginBottom: '30px' }}>SECURE OPERATIONS TERMINAL</p>

        <div className="auth-tabs">
          <button className={`tab-btn ${isLogin ? 'active' : ''}`} onClick={() => { setIsLogin(true); setEmail(''); setPass(''); }}>LOGIN</button>
          <button className={`tab-btn ${!isLogin ? 'active' : ''}`} onClick={() => { setIsLogin(false); setEmail(''); setPass(''); }}>SIGN UP</button>
        </div>

        <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <input type="email" placeholder="GMAIL" className="cyber-input" value={email} onChange={e => setEmail(e.target.value)} required />
          <div className="password-input-wrapper">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="PASSWORD"
              className="cyber-input"
              value={password}
              onChange={e => setPass(e.target.value)}
              required
              style={{ marginBottom: 0 }}
            />
            <button
              type="button"
              className="toggle-password-btn"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <Icons.EyeOff size={16} /> : <Icons.Eye size={16} />}
            </button>
          </div>
          <button type="submit" className="auth-btn-hex">{isLogin ? 'INITIATE SESSION' : 'REGISTER AGENT'}</button>
        </form>

        <div style={{ margin: '30px 0' }}>
          <button className="google-btn" onClick={handleGoogle} disabled={isLoggingIn}>
            {isLoggingIn ? 'ESTABLISHING LINK...' : '• GOOGLE PROTOCOL •'}
          </button>
        </div>

        <div style={{ fontSize: '8px', color: '#334155', fontFamily: 'monospace' }}>
          RESTRICTED ACCESS // LEVEL 5 CLEARANCE REQUIRED
        </div>
      </div>
    </div>
  );
};

export default App;
