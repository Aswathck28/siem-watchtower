import React, { useState } from 'react';
import Icons from './Icons';

// Modal component that allows users to manually report security incidents or suspicious behavior to the backend
/**
 * Component: TacticalReporter
 * Description: Floating Action Button (FAB) and modal interface that 
 *              allows analysts and users to manually report security 
 *              incidents. Transmits encrypted payloads directly to the 
 *              centralized SOC ingestion endpoint.
 * Parameters:
 *   - userUid (str): The unique identity of the reporting user.
 *   - onComplete (func): Optional callback triggered after successful submission.
 * Returns:
 *   - JSX.Element
 */
const TacticalReporter = ({ userUid, onComplete }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [loading, setLoading] = useState(false);
    const [details, setDetails] = useState('');

    // Handles the asynchronous submission of the user's manual tactical report to the backend API
/**
 * Function: handleSubmit
 * Description: Asynchronous form handler that packages the user's manual 
 *              incident details and transmits them via POST request to 
 *              the security reporting API. Triggers a global alert 
 *              confirmation upon success.
 * Parameters:
 *   - e (Event): The form submission event.
 * Returns:
 *   - Promise<void>
 */
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch('http://localhost:5000/api/user/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uid: userUid, details: { comment: details, timestamp: new Date() } })
            });
            if (res.ok) {
                alert('Incident reported to SOC Command. High alert active.');
                setIsOpen(false);
                setDetails('');
                if (onComplete) onComplete();
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <button className="tactical-fab" onClick={() => setIsOpen(true)}>
                <Icons.Flag />
                <span>REPORT INCIDENT</span>
            </button>

            {isOpen && (
                <div className="stark-overlay">
                    <div className="stark-modal theme-red" style={{ height: 'auto', width: '400px' }}>
                        <div className="stark-header">
                            <span className="stark-title">TAC-REPORT PROTOCOL</span>
                            <button className="stark-close-btn" onClick={() => setIsOpen(false)}>×</button>
                        </div>
                        <div className="stark-body">
                            <form onSubmit={handleSubmit}>
                                <div style={{ fontSize: '10px', color: '#64748b', marginBottom: '10px' }}>
                                    ENCRYPTED UPLINK TO SIEM-WATCHTOWER SOC
                                </div>
                                <textarea 
                                    className="cyber-input" 
                                    style={{ height: '100px', resize: 'none' }}
                                    placeholder="Describe suspicious activity..."
                                    value={details}
                                    onChange={(e) => setDetails(e.target.value)}
                                    required
                                />
                                <button type="submit" className="auth-btn-hex" disabled={loading}>
                                    {loading ? 'UPLOADING...' : 'EXECUTE UPLINK'}
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};

export default TacticalReporter;
