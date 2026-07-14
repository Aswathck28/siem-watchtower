Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "cmd /c cd /d d:\siem-watchtower\siem-watchtower\server && node index.js", 0
Set WshShell = Nothing
