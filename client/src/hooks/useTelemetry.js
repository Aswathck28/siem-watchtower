import { useEffect, useRef, useCallback } from 'react';
import { getCLS, getFID, getLCP } from 'web-vitals';
import axios from 'axios';

// --- HELPER: Get a friendly site name from a URL ---
// e.g. "https://www.youtube.com/watch?v=abc" → "YouTube"
const FRIENDLY_NAMES = {
    'youtube.com': 'YouTube',
    'youtu.be': 'YouTube',
    'google.com': 'Google',
    'whatsapp.com': 'WhatsApp',
    'wa.me': 'WhatsApp',
    'web.whatsapp.com': 'WhatsApp Web',
    'facebook.com': 'Facebook',
    'instagram.com': 'Instagram',
    'twitter.com': 'Twitter / X',
    'x.com': 'X (Twitter)',
    'reddit.com': 'Reddit',
    'github.com': 'GitHub',
    'netflix.com': 'Netflix',
    'amazon.com': 'Amazon',
    'linkedin.com': 'LinkedIn',
    'gmail.com': 'Gmail',
    'mail.google.com': 'Gmail',
    'drive.google.com': 'Google Drive',
    'docs.google.com': 'Google Docs',
    'outlook.com': 'Outlook',
    'teams.microsoft.com': 'Microsoft Teams',
    'slack.com': 'Slack',
    'discord.com': 'Discord',
    'zoom.us': 'Zoom',
    'twitch.tv': 'Twitch',
    'tiktok.com': 'TikTok',
    'spotify.com': 'Spotify',
};

/**
 * Function: getFriendlyName
 * Description: Utility to parse raw URLs into human-readable brand names 
 *              (e.g., 'https://youtube.com/...' -> 'YouTube') to improve 
 *              the legibility of traffic logs in the SOC dashboard.
 * Parameters:
 *   - url (str): The raw URL to be parsed.
 * Returns:
 *   - str: The sanitized brand name or the original hostname.
 */
const getFriendlyName = (url) => {
    try {
        const { hostname } = new URL(url);
        const stripped = hostname.replace(/^www\./, '');
        // Check exact match first, then root domain
        if (FRIENDLY_NAMES[hostname]) return FRIENDLY_NAMES[hostname];
        if (FRIENDLY_NAMES[stripped]) return FRIENDLY_NAMES[stripped];
        return stripped; // fallback: clean hostname like "youtube.com"
    } catch {
        return url;
    }
};

// Custom Hook: Comprehensive Telemetry tracking system. Captures performance, journey, errors, data leakage, and idleness.
/**
 * Hook: useTelemetry
 * Description: High-performance React hook that manages the lifecycle of 
 *              endpoint telemetry. Orchestrates a suite of 15+ event 
 *              listeners capturing performance vitals, user journey shifts, 
 *              potential data leaks, and interactive idleness.
 * Parameters:
 *   - user (object): The authenticated user entity.
 *   - sessionId (str): Unique session identifier for event grouping.
 *   - activeTab (str): Contextual indicator of the currently focused UI domain.
 * Returns:
 *   - object: { logBeacon } - Method to manually submit telemetry events.
 */
const useTelemetry = (user, sessionId, activeTab) => {
    const historyRef = useRef([]);
    const lastOutboundClick = useRef({ url: null, timestamp: 0 });

    // --- HELPER: LOG TO BACKEND ---
    // Core telemetry submission function. Wraps details with context and sends beacon data to logging endpoint.
/**
 * Callback: logBeacon
 * Description: Core telemetry submission function. Wraps details with user 
 *              and session context and sends beacon data to the logging 
 *              ingestion endpoint via a non-blocking request.
 * Parameters:
 *   - action (str): The identifier for the event (e.g., 'route_change').
 *   - details (object): Arbitrary payload specific to the event type.
 * Returns:
 *   - Promise: Resolves with backend response or silent failure.
 */
    const logBeacon = useCallback((action, details = {}) => {
        if (!user || !sessionId) return;

        return axios.post('http://localhost:5000/api/log', {
            uid: user.uid,
            sessionId: sessionId,
            action,
            details: {
                ...details,
                active_tab: activeTab, // Contextual capture
                path: window.location.pathname,
                timestamp: Date.now()
            }
        }).then(res => res.data).catch(() => { /* Silent Fail */ });
    }, [user, sessionId, activeTab]);

    // --- 1. PERFORMANCE METRICS (Web Vitals) ---
    useEffect(() => {
        if (!user) return;

        // Callback function to capture and filter Web Vitals metric data, formatting it for backend submission
/**
 * Callback: handleMetric
 * Description: Captured Web Vital metrics (CLS, FID, LCP) and prepares 
 *              them for backend ingestion, mapping raw values to their 
 *              respective performance domains.
 * Parameters:
 *   - metric (object): raw performance metric object from web-vitals.
 * Returns:
 *   - void
 */
        const handleMetric = (metric) => {
            // Filter out non-crucial metrics to save bandwidth if needed
            logBeacon('performance_metric', {
                name: metric.name,
                value: metric.value,
                id: metric.id, // Unique ID for this metric instance
                rating: metric.rating // 'good', 'needs-improvement', 'poor'
            });
        };

        getCLS(handleMetric);
        getFID(handleMetric);
        getLCP(handleMetric);
    }, [user, logBeacon]);

    // --- 2. USER JOURNEY TRACKING ---
    useEffect(() => {
        if (!user) return;

        // Push initial state
        const currentPath = window.location.pathname;
        historyRef.current.push({ path: currentPath, time: Date.now() });

        // Listen for history changes (monkey-patching history for SPA)
        const originalPushState = window.history.pushState;
        window.history.pushState = function (...args) {
            originalPushState.apply(this, args);
            const newPath = window.location.pathname;

            // Log the transition
            const prev = historyRef.current[historyRef.current.length - 1];
            if (prev && prev.path !== newPath) {
                logBeacon('route_change', {
                    from: prev.path,
                    to: newPath,
                    time_on_page_ms: Date.now() - prev.time
                });
                historyRef.current.push({ path: newPath, time: Date.now() });
            }
        };

        return () => {
            window.history.pushState = originalPushState;
        };
    }, [user, logBeacon]);

    // --- 3. ERROR & RAGE CLICK TRACKING ---
    useEffect(() => {
        if (!user) return;

        // Global Error Listener
        // Traps unhandled JavaScript exceptions and logs their location and message
        const errorHandler = (event) => {
            logBeacon('js_error', {
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno
            });
        };

        // Unhandled Promise Rejection
        // Traps promises that reject without a catch block
        const rejectionHandler = (event) => {
            logBeacon('js_error', {
                message: event.reason ? event.reason.toString() : 'Unhandled Rejection',
                type: 'promise_rejection'
            });
        };

        // Rage Click Detector (3 clicks in 1 second)
        let clickTimes = [];
        // Monitors click cadence; triggers an anomaly report if rapid successive clicking targets the same area
        const clickHandler = (e) => {
            const now = Date.now();
            clickTimes.push(now);
            // Keep only clicks within last 1000ms
            clickTimes = clickTimes.filter(t => now - t < 1000);

            if (clickTimes.length >= 3) {
                logBeacon('rage_click', {
                    x: e.clientX,
                    y: e.clientY,
                    target: e.target.tagName
                });
                clickTimes = []; // Reset after logging
            }
        };

        window.addEventListener('error', errorHandler);
        window.addEventListener('unhandledrejection', rejectionHandler);
        window.addEventListener('click', clickHandler);

        // --- 4. DATA LEAKAGE & RECON MONITORING ---
        // Logs clipboard copy operations and the length of the string copied
        const handleCopy = () => logBeacon('clipboard_copy', { length: window.getSelection()?.toString().length || 0 });
        // Logs clipboard paste interactions that may indicate inserting sensitive info or malicious payload
        const handlePaste = () => logBeacon('clipboard_paste', {});
        
        // Logs when users focus on input/textarea elements, including context on the targeted field
        const handleFocus = (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                logBeacon('form_focus', { 
                    type: e.target.type, 
                    name: e.target.name, 
                    id: e.target.id,
                    placeholder: e.target.placeholder 
                });
            }
        };

        // Logs opening of the browser context menu, potentially used for inspecting or saving elements
        const handleContextMenu = () => logBeacon('context_menu', {});

        // Logs specific diagnostic or dev-tool keyboard shortcut utilization (F12, Ctrl+U)
        const handleKey = (e) => {
            if (e.key === 'F12') logBeacon('console_open', { method: 'F12' });
            if (e.ctrlKey && e.key === 'u') logBeacon('source_view', {});
        };

        // Analyzes and logs changes to document visibility, noting potential context-switches and outbound destinations
        const handleVis = () => {
            if (document.hidden) {
                const now = Date.now();
                const details = { last_active: activeTab, page_title: document.title, timestamp: now };
                
                // Correlate with last outbound click (within 5s — extended window for slow navigations)
                if (lastOutboundClick.current.url && (now - lastOutboundClick.current.timestamp < 5000)) {
                    details.destination_url = lastOutboundClick.current.url;
                    details.destination = getFriendlyName(lastOutboundClick.current.url);
                }
                
                logBeacon('nav_away', details);
            } else {
                // On return: check document.referrer to find where user was during away period
                const returnDetails = { returned_to: activeTab, page_title: document.title, timestamp: Date.now() };
                try {
                    if (document.referrer) {
                        const referrerOrigin = new URL(document.referrer).origin;
                        if (referrerOrigin !== window.location.origin) {
                            returnDetails.from_site = getFriendlyName(document.referrer);
                            returnDetails.from_url = document.referrer;
                        }
                    }
                } catch (e) { /* ignore invalid referrer */ }
                
                // Fallback to last outbound click if referrer is empty (tab switching)
                if (!returnDetails.from_site && lastOutboundClick.current.url) {
                    returnDetails.from_site = getFriendlyName(lastOutboundClick.current.url);
                    returnDetails.from_url = lastOutboundClick.current.url;
                }
                
                logBeacon('nav_return', returnDetails);
            }
        };

        // Mousedown fires BEFORE the browser navigates — more reliable than 'click'
        // Pre-emptively identifies an outbound navigation attempt upon initial mouse depress
        const handleMouseDown = (e) => {
            const link = e.target.closest('a');
            if (!link || !link.href) return;
            try {
                const url = new URL(link.href);
                if (url.origin !== window.location.origin) {
                    lastOutboundClick.current = { url: link.href, timestamp: Date.now() };
                }
            } catch (err) { /* ignore */ }
        };

        // Differentiates between file downloads and external outbound links tracking click intent
        const handleDownloadClick = (e) => {
            const link = e.target.closest('a');
            if (!link) return;

            // 1. Check for Downloads
            if (link.hasAttribute('download') || link.href.match(/\.(zip|pdf|docx|xlsx|exe|bin|rar)$/i)) {
                logBeacon('file_download', { url: link.href, fileName: link.download || link.href.split('/').pop() });
            }

            // 2. Check for Outbound Links (click event — also update the ref with friendly name)
            try {
                const url = new URL(link.href);
                if (url.origin !== window.location.origin) {
                    const now = Date.now();
                    lastOutboundClick.current = { url: link.href, timestamp: now };
                    logBeacon('outbound_click', { 
                        url: link.href,
                        site: getFriendlyName(link.href),
                        text: link.innerText?.substring(0, 50),
                        timestamp: now 
                    });
                }
            } catch (err) { /* Invalid URL - likely internal hash or mailto */ }
        };

        // Captures window resize events which relate to device manipulation or dev tool opening 
        const handleResize = () => {
            logBeacon('window_resize', { 
                width: window.innerWidth, 
                height: window.innerHeight,
                ratio: (window.innerWidth / window.innerHeight).toFixed(2)
            });
        };

        // Handlers to catch device network status switching (online/offline)
        const handleOnline = () => logBeacon('network_status', { state: 'online' });
        const handleOffline = () => logBeacon('network_status', { state: 'offline' });

        // --- 5. IDLE DETECTION ---
        let idleTimer;
        // Resets the inactivity timer to denote user is still interacting with the application
        const resetIdle = () => {
            if (idleTimer === 'IDLE') logBeacon('idle_end', { timestamp: Date.now() });
            clearTimeout(idleTimer);
            idleTimer = setTimeout(() => {
                logBeacon('idle_start', { timestamp: Date.now(), threshold: '60s' });
                idleTimer = 'IDLE'; 
            }, 60000);
        };

        // --- 6. PAGE PERFORMANCE (Initial Load) ---
        if (window.performance && window.performance.timing) {
            const t = window.performance.timing;
            const loadTime = t.loadEventEnd - t.navigationStart;
            if (loadTime > 0) {
                logBeacon('page_timing', { 
                    load_time_ms: loadTime,
                    dom_ready_ms: t.domComplete - t.domLoading,
                    dns_ms: t.domainLookupEnd - t.domainLookupStart
                });
            }
        }

        document.addEventListener('copy', handleCopy);
        document.addEventListener('paste', handlePaste);
        document.addEventListener('keydown', handleKey);
        document.addEventListener('visibilitychange', handleVis);
        document.addEventListener('focusin', handleFocus);
        document.addEventListener('contextmenu', handleContextMenu);
        document.addEventListener('mousedown', handleMouseDown); // Capture outbound before navigation
        document.addEventListener('click', handleDownloadClick);
        window.addEventListener('resize', handleResize);
        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);
        
        ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt => 
            window.addEventListener(evt, resetIdle)
        );
        resetIdle();

        // --- 7. SCROLL DEPTH TRACKING ---
        let maxScroll = 0;
        // Identifies peak scroll depth percent down a long page
        const scrollHandler = () => {
            const scrollTop = window.scrollY;
            const docHeight = document.body.offsetHeight;
            const winHeight = window.innerHeight;
            if (docHeight <= winHeight) return;

            const scrollPercent = Math.round((scrollTop / (docHeight - winHeight)) * 100);
            if (scrollPercent > maxScroll + 10) {
                maxScroll = scrollPercent;
                logBeacon('scroll_depth', { depth: `${maxScroll}%` });
            }
        };

        let scrollTimeout;
        // Debounces scroll events to minimize computing load and spamming function calls
        const debouncedScroll = () => {
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(scrollHandler, 500);
        };

        window.addEventListener('scroll', debouncedScroll);

        return () => {
            window.removeEventListener('error', errorHandler);
            window.removeEventListener('unhandledrejection', rejectionHandler);
            window.removeEventListener('click', clickHandler);

            document.removeEventListener('copy', handleCopy);
            document.removeEventListener('paste', handlePaste);
            document.removeEventListener('keydown', handleKey);
            document.removeEventListener('visibilitychange', handleVis);
            document.removeEventListener('focusin', handleFocus);
            document.removeEventListener('contextmenu', handleContextMenu);
            document.removeEventListener('mousedown', handleMouseDown);
            document.removeEventListener('click', handleDownloadClick);
            window.removeEventListener('resize', handleResize);
            window.removeEventListener('online', handleOnline);
            window.removeEventListener('offline', handleOffline);
            
            ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt => 
                window.removeEventListener(evt, resetIdle)
            );
            clearTimeout(idleTimer);

            window.removeEventListener('scroll', debouncedScroll);
        };
    }, [user, logBeacon, activeTab]);

    return { logBeacon };
};

export default useTelemetry;
