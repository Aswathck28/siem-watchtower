import React from 'react';
import Icons from './Icons';

// Provides a styled, reusable modal container using the Stark/Cyberpunk theme for dashboard overlays
// Receives title, onClose callback, theme string, and children components to render inside
/**
 * Component: StarkModal
 * Description: High-fidelity reusable modal container using the Stark/Cyberpunk 
 *              design system. Features HUD-style corner decorations and 
 *              scanline overlays for an immersive SOC analyst experience.
 * Parameters:
 *   - title (str): Header text displayed in the modal title bar.
 *   - onClose (func): Callback to signal the parent component to unmount.
 *   - theme (str): Color variant for the HUD decorations (default: 'blue').
 *   - children (JSX): The content components to be rendered inside the body.
 * Returns:
 *   - JSX.Element
 */
const StarkModal = ({ title, onClose, theme = "blue", children }) => (
    <div className={`stark-overlay theme-${theme}`}>
        <div className="stark-modal" onClick={e => e.stopPropagation()}>
            {/* HUD DECORATIONS */}
            <div className="stark-corner tl"></div>
            <div className="stark-corner tr"></div>
            <div className="stark-corner bl"></div>
            <div className="stark-corner br"></div>
            <div className="stark-scanline"></div>

            {/* HEADER */}
            <div className="stark-header">
                <div className="stark-title">
                    <Icons.Grid style={{ marginRight: 10, marginBottom: -2 }} /> {title}
                </div>
                <button className="stark-close-btn" onClick={onClose}>✕</button>
            </div>

            {/* CONTENT */}
            <div className="stark-body">
                {children}
            </div>
        </div>
    </div>
);

export default StarkModal;
