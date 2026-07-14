// Import React and ReactDOM for application rendering
import React from 'react';
import ReactDOM from 'react-dom/client';
// Import global application styles
import './index.css';
// Import main application component
import App from './App';

// Creates the root react element bound to the 'root' div in standard HTML template
/**
 * Entry Point: client/src/index.js
 * Description: The primary bootstrap script for the SIEM Watchtower 
 *              frontend. Initializes the React root and renders the 
 *              top-level App component.
 */
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
    <App />
);
