@echo off
echo ===================================================
echo               SIEM Watchtower Launcher
echo ===================================================
echo.

REM 1. Start PostgreSQL check
echo [1/4] Checking Database connection...
cd /d "%~dp0server"
node check_db.js
if %errorlevel% neq 0 (
    echo [ERROR] Database is not running or credentials in server/check_db.js are incorrect.
    echo Please make sure PostgreSQL is running on port 5432.
    pause
    exit /b 1
)
echo Database is ONLINE.
echo.

REM 2. Start the Backend Express Server
echo [2/4] Starting Backend Server (Port 5000)...
start "SIEM Backend Server" cmd /c "node index.js"
timeout /t 3 /nobreak >nul

REM 3. Start the ML Service
echo [3/4] Starting Python ML Microservice (Port 5001)...
cd /d "%~dp0ml_services"
start "SIEM ML Service" cmd /c "start_ml_service.bat"
timeout /t 3 /nobreak >nul

REM 4. Start the Monitoring Agents
echo [4/4] Starting System Monitoring Agents...
cd /d "%~dp0"
call restart_agents.bat

echo.
echo ===================================================
echo SIEM Watchtower is now running!
echo ---------------------------------------------------
echo - Dashboard UI & Backend API: http://localhost:5000
echo - ML Anomaly Service: http://localhost:5001
echo ===================================================
echo.
pause
