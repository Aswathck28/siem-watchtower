import { useEffect, useRef } from 'react';

// Utility Function: Generates or retrieves a persistent session ID from localStorage to uniquely track user sessions across tabs
/**
 * Function: getOrCreateSessionId
 * Description: Utility to maintain session continuity across tab reloads 
 *              by generating or retrieving a persistent UUID from 
 *              localStorage. Uniquely tracks user interactions within 
 *              a single browser context.
 * Parameters:
 *   - None
 * Returns:
 *   - str: The active session identifier.
 */
const getOrCreateSessionId = () => {
    let sid = localStorage.getItem('siem_session_id');
    if (!sid) {
        sid = 'sess-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('siem_session_id', sid);
    }
    return sid;
};

/**
 * useTabTracking - Hook object
 * Captures Page Visibility events and sends telemetry to the SIEM.
 * Uses the Page Visibility API. Sends TAB_SWITCH_AWAY and TAB_SWITCH_RETURN events.
 * Respects privacy: skips if consentTracking is false.
 * @param {string} uid - The Firebase User ID
 * @param {string|null} sessionId - Externally provided session ID (optional)
 * @param {boolean} consentTracking - User consent flag from settings
 */
/**
 * Hook: useTabTracking
 * Description: Specialized hook that captures 'Visibility API' events 
 *              (Hidden/Visible) to monitor when users switch away from 
 *              the SIEM terminal. Implements a 300ms debounce to avoid 
 *              duplicate ingestions from rapid switching.
 * Parameters:
 *   - uid (str): The Firebase User ID.
 *   - sessionId (str|null): Optional explicit session identifier.
 *   - consentTracking (bool): User privacy toggle from settings.
 * Returns:
 *   - void
 */
const useTabTracking = (uid, sessionId, consentTracking = true) => {
    const debounceRef = useRef(null);

    useEffect(() => {
        if (!uid || !consentTracking) return;

        // Use provided session ID or auto-generate a persistent one
        const activeSessionId = sessionId || getOrCreateSessionId();

        const handleVisibilityChange = () => {
            // Debounce: Ignore rapid consecutive events (< 300ms)
            if (debounceRef.current) clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(async () => {
                const eventType = document.hidden ? 'TAB_SWITCH_AWAY' : 'TAB_SWITCH_RETURN';
                const timestamp = new Date().toISOString(); // UTC ISO string

                try {
                    await fetch('http://localhost:5000/api/telemetry/tab-switch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            uid,
                            sessionId: activeSessionId,
                            event_type: eventType,
                            timestamp
                        })
                    });
                    console.log(`[SIEM TELEMETRY] ${eventType} @ ${timestamp}`);
                } catch (error) {
                    // Fail silently: do not disrupt user experience
                    console.warn('[SIEM TELEMETRY] Network error - event not sent.', error.message);
                }
            }, 300);
        };

        document.addEventListener('visibilitychange', handleVisibilityChange);

        return () => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
            if (debounceRef.current) clearTimeout(debounceRef.current);
        };
    }, [uid, sessionId, consentTracking]);
};

export default useTabTracking;
