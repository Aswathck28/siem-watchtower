@echo off
echo ===================================================
echo     SIEM-Watchtower - Multi-Service Orchestrator    
echo ===================================================
echo [1/4] Starting Node.js Backend Server silently...
start /B "SIEM Backend" cmd /c "cd /d D:\siem-watchtower\siem-watchtower\server && npm start"

echo [2/4] Starting Python ML Microservice silently...
start /B "SIEM ML Service" cmd /c "cd /d D:\siem-watchtower\siem-watchtower\ml_service && python app.py"

echo [3/4] Starting React Dashboard (Frontend) silently...
start /B "SIEM UI" cmd /c "cd /d D:\siem-watchtower\siem-watchtower\client && npm start"

echo [4/4] Starting Watchtower Elite Agent silently (Log Collection)...
start /B "SIEM Agent" cmd /c "cscript //nologo D:\siem-watchtower\siem-watchtower\scripts\start_agent_background.vbs"

echo.
echo All services have been dispatched in background windows!
echo No UI windows should pop up automatically.
echo - Backend available at: http://localhost:5000
echo - ML API available at: http://localhost:5001
echo - Frontend available at: http://localhost:3000
echo ===================================================
pause
