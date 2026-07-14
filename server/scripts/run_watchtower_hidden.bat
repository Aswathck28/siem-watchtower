@echo off
:: Start Python ML Service silently in the background
start /B "SIEM_ML" cmd.exe /c "cd /d D:\siem-watchtower\siem-watchtower\ml_service && python app.py"

:: Start Node.js SIEM Backend silently in the background
start /B "SIEM_NODE" cmd.exe /c "cd /d D:\siem-watchtower\siem-watchtower\server && node index.js"

:: Start React Dashboard silently
start /B "SIEM_UI" cmd.exe /c "cd /d D:\siem-watchtower\siem-watchtower\client && npm start"
