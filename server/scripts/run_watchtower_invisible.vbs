Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "D:\siem-watchtower\siem-watchtower\run_watchtower_hidden.bat" & Chr(34), 0
Set WshShell = Nothing
