$baseDir = "D:\siem-watchtower\siem-watchtower"

Write-Host "Setting up SIEM-Watchtower 24/7 Invisible Auto-Start..." -ForegroundColor Cyan

# 1. Create a quiet startup batch script
$batLogic = @"
@echo off
:: Start Python ML Service silently in the background
start /B "SIEM_ML" cmd.exe /c "cd /d $baseDir\ml_services && python app.py"

:: Start Node.js SIEM Backend silently in the background
start /B "SIEM_NODE" cmd.exe /c "cd /d $baseDir\server && node index.js"

:: Start React Dashboard silently
start /B "SIEM_UI" cmd.exe /c "cd /d $baseDir\client && npm start"
"@

$batPath = "$baseDir\run_watchtower_hidden.bat"
$batLogic | Out-File -FilePath $batPath -Encoding ASCII


# 2. Create the VBS script to run the batch file completely invisibly (no black window)
$vbsLogic = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "$batPath" & Chr(34), 0
Set WshShell = Nothing
"@

$vbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SIEM_Watchtower_24x7.vbs"
$vbsLogic | Out-File -FilePath $vbsPath -Encoding ASCII

Write-Host "✅ SUCCESS!" -ForegroundColor Green
Write-Host "The SIEM Watchtower will now automatically boot up invisibly in the background every time you turn on your computer."
Write-Host "You never have to run start.bat again."
