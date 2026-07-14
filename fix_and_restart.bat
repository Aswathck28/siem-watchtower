@echo off
REM Fix and Restart SIEM Watchtower

echo ==========================================
echo SIEM Watchtower - Fix and Restart Tool
echo ==========================================
echo.

REM Kill all Node.js processes (server)
echo [1/6] Stopping server...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul
echo      Server stopped.
echo.

REM Kill all Python agents
echo [2/6] Stopping agents...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
timeout /t 2 /nobreak >nul
echo      Agents stopped.
echo.

REM Start the server
echo [3/6] Starting server...
cd /d "%~dp0server"
start /min "SIEM Server" node index.js
timeout /t 5 /nobreak >nul
echo      Server started.
echo.

REM Start the system_monitor agent
echo [4/6] Starting system_monitor agent...
cd /d "%~dp0agents\system_monitor"
start /min "System Monitor Agent" pythonw main.py
timeout /t 3 /nobreak >nul
echo      System monitor agent started.
echo.

REM Start the app_tracker agent
echo [5/6] Starting app_tracker agent...
cd /d "%~dp0agents\app_tracker"
start /min "App Tracker Agent" pythonw app_tracker.py
timeout /t 3 /nobreak >nul
echo      App tracker agent started.
echo.

REM Check server health
echo [6/6] Checking server health...
cd /d "%~dp0"
curl -s http://localhost:5000/api/health >nul 2>&1
if %errorlevel% == 0 (
    echo      Server is healthy!
) else (
    echo      WARNING: Server may not be responding.
)
echo.

echo ==========================================
echo All services restarted!
echo ==========================================
echo.
echo Please refresh your browser (F5)
echo.
pause
