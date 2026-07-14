# SIEM-Watchtower agent: register a silent, persistent scheduled task (pythonw, no window).
# Run via install_service.bat (Administrator recommended).

param(
    [Parameter(Mandatory = $true)]
    [string] $AgentDir
)

$ErrorActionPreference = "Stop"

$AgentDir = (Resolve-Path -LiteralPath $AgentDir).Path
$MainPy = Join-Path $AgentDir "main.py"
if (-not (Test-Path -LiteralPath $MainPy)) {
    throw "main.py not found: $MainPy"
}

$pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonw) {
    throw "pythonw.exe not found in PATH. Install Python and ensure 'Add to PATH' is enabled."
}

$taskName = "SIEMWatchtowerAgent"
$runAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Remove existing registration (clean reinstall)
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Action: pythonw = no console window; WorkingDirectory = stable imports / relative paths
$action = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$MainPy`"" -WorkingDirectory $AgentDir

# Trigger: user logon — runs in the interactive session (required for WTS hooks and user app tracking).
# After reboot, the agent starts on first login (typical desktop workflow). Uses pythonw (no console).
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn -User $runAs -RandomDelay (New-TimeSpan -Seconds 20)

# Trigger: system startup (best-effort). With an Interactive principal this may start once the user session is available,
# but ensures Windows has a startup trigger registered (and StartWhenAvailable will catch missed runs).
$triggerStartup = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 30)

# Settings: always attempt restart; long-running; battery-friendly; restart policy for hard exits
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1)

# Run as installing user, interactive session, highest available for hooks
$principal = New-ScheduledTaskPrincipal `
    -UserId $runAs `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger @($triggerStartup, $triggerLogon) `
    -Settings $settings `
    -Principal $principal `
    -Force | Out-Null

Write-Host "[OK] Registered scheduled task: $taskName"
Write-Host "     Execute: $pythonw"
Write-Host "     Args:    `"$MainPy`""
Write-Host "     WorkDir: $AgentDir"
