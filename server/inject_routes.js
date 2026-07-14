/**
 * Utility: inject_routes.js
 * Description: Automation script that dynamically patches 'index.js' 
 *              to include enterprise-level routing. Ensures modular 
 *              separation of route registration while maintaining 
 *              a single service entry point.
 */
const fs = require('fs');
let c = fs.readFileSync('index.js', 'utf8');
const insert = '\r\n// --- ENTERPRISE ROUTES ---\r\nrequire(\'./enterprise_routes\')(app, pool);\r\n\r\n';
c = c.replace('app.listen(PORT,', insert + 'app.listen(PORT,');
fs.writeFileSync('index.js', c);
console.log('Done. Lines:', c.split('\n').length);
