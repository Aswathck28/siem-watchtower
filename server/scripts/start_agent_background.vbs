Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File d:\siem-watchtower\siem-watchtower\scripts\watchtower_elite_agent.ps1", 0
Set WshShell = Nothing
