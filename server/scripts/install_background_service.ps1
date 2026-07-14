$agentPath = "D:\siem-watchtower\siem-watchtower\watchtower_elite_agent.ps1"

Write-Host "Installing SIEM Watchtower Elite Agent as a silent background service..." -ForegroundColor Cyan

# 1. Create the action to run PowerShell hidden
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentPath`""

# 2. Trigger at user Logon so it runs in your session (needed to track YOUR foreground windows)
$trigger = New-ScheduledTaskTrigger -AtLogOn

# 3. Create the task settings to run silently and without stopping after 3 days
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 0)

# 4. Run with maximum privileges as the EXACT logged-in user (DO NOT use 'Administrators' group or it goes to Session 0 and can't see the desktop)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

# 5. Register the task
Register-ScheduledTask -TaskName "SIEM_Watchtower_Agent" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Installation Complete! The log agent will now run automatically in the background on startup." -ForegroundColor Green

# --- ADD: FACIAL RECOGNITION AGENT (ON WORKSTATION UNLOCK) ---
$faceScript = "D:\siem-watchtower\siem-watchtower\scripts\face_recognition_agent.py"
Write-Host "Registering Facial Recognition Agent for Workstation Unlock..." -ForegroundColor Cyan

# Use pythonw.exe or python.exe to run the script silently
$actionFace = New-ScheduledTaskAction -Execute "python.exe" -Argument "`"$faceScript`"" -WorkingDirectory "D:\siem-watchtower\siem-watchtower\scripts"
$triggerFace = New-ScheduledTaskTrigger -AtWorkStationUnlock

Register-ScheduledTask -TaskName "SIEM_Watchtower_FaceRec" -Action $actionFace -Trigger $triggerFace -Settings $settings -Force | Out-Null
Write-Host "Facial Recognition Agent registered successfully!" -ForegroundColor Green

# 6. Start it right now so you don't have to reboot
Write-Host "Starting the background agent right now..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName "SIEM_Watchtower_Agent"
Write-Host "Done! You can now close this console entirely. The system is armed." -ForegroundColor Green
