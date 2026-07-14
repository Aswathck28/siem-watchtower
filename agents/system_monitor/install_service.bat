@echo off
setlocal EnableExtensions
echo ========================================================
echo SIEM Watchtower - Persistent Agent (one-time install)
echo ========================================================
echo.
echo This registers a Scheduled Task that runs pythonw.exe (no window).
echo After this, you do not need to run main.py manually.
echo.

set "DIR=%~dp0"
set "DIR=%DIR:~0,-1%"

:: Require pythonw for silent background (no console)
for /f "delims=" %%i in ('where.exe pythonw.exe 2^>nul') do set "PYTHONW=%%i"
if not defined PYTHONW (
    echo [ERROR] pythonw.exe not found. Install Python and add it to PATH.
    pause
    exit /b 1
)

echo [INFO] Using pythonw: %PYTHONW%
echo [INFO] Installing Python dependencies...
python -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)

echo [INFO] Registering scheduled task (requires elevation)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_task.ps1" -AgentDir "%DIR%"
if errorlevel 1 (
    echo [ERROR] Task registration failed. Right-click this file and "Run as administrator".
    pause
    exit /b 1
)

echo [INFO] Starting agent now (background, no window^)...
schtasks /run /tn "SIEMWatchtowerAgent" >nul 2>&1

echo.
echo ========================================================
echo INSTALL COMPLETE
echo ========================================================
echo Task name: SIEMWatchtowerAgent
echo - Starts automatically at every user logon (silent^).
echo - Single instance enforced in main.py (mutex^).
echo - Crash recovery: outer restart loop + task restart policy.
echo - Logs: agents\system_monitor\agent_debug.log
echo.
echo Verify: schtasks /query /tn "SIEMWatchtowerAgent" /v /fo LIST
echo ========================================================
pause
