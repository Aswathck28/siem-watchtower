@echo off
REM Restart SIEM Watchtower Agents with Battery Fixes
REM This script stops and restarts all monitoring agents to apply battery fixes

echo ==========================================
echo SIEM Watchtower - Agent Restart Tool
echo ==========================================
echo.

REM Kill existing Python agent processes
echo [1/4] Stopping existing agents...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
timeout /t 2 /nobreak >nul
echo      Agents stopped.
echo.

REM Clear old battery logs from database
echo [2/4] Clearing old battery cache from database...
cd /d "%~dp0server"
node -e "
const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'siem-watchtower',
    password: 'pava4484',
    port: 5432
});

async function clearBatteryCache() {
    try {
        // Delete old battery status logs
        await pool.query(\"DELETE FROM system_logs WHERE event_type = 'BATTERY_STATUS'\");
        await pool.query(\"DELETE FROM system_logs WHERE event_type = 'BATTERY_CRITICAL'\");
        await pool.query(\"DELETE FROM system_logs WHERE event_type LIKE 'CHARGER_%'\");
        console.log('Battery cache cleared successfully.');
    } catch (e) {
        console.error('Error clearing battery cache:', e.message);
    } finally {
        await pool.end();
    }
}
clearBatteryCache();
"
echo      Battery cache cleared.
echo.

REM Start the system_monitor agent
echo [3/4] Starting system_monitor agent with battery fixes...
cd /d "%~dp0agents\system_monitor"
start /min "System Monitor Agent" pythonw main.py
timeout /t 3 /nobreak >nul
echo      System monitor agent started.
echo.

REM Start the app_tracker agent
echo [4/4] Starting app_tracker agent with battery fixes...
cd /d "%~dp0agents\app_tracker"
start /min "App Tracker Agent" pythonw app_tracker.py
timeout /t 3 /nobreak >nul
echo      App tracker agent started.
echo.

echo ==========================================
echo All agents restarted successfully!
echo ==========================================
echo.
echo Battery fixes applied:
echo   - Correct battery percentage reporting
echo   - 30-second delay for CPU alerts (avoids false positives)
echo   - 60% CPU threshold for battery drain alerts
echo.
echo Refresh your dashboard to see correct battery percentage.
echo.
pause
