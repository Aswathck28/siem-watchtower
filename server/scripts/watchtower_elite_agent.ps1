
# ######################################################################
# SIEM WATCHTOWER ELITE AGENT v5.0
# STRICT BEHAVIOUR MONITORING & FILTERING
# ######################################################################

$serverUrl = "http://localhost:5000/api/agent/log"
$hostname = $env:COMPUTERNAME
$global:lastSentHashes = @{} # Hash -> Timestamp

# --- STATE TRACKING ---
$global:lastUsbDrives = @()
$global:lastBluetoothStatus = $null
$global:lastRadioState = $null
$global:cpuHistory = @() # Store last 3 samples
$global:lastHighCpuAlert = [DateTime]::MinValue
$global:trackedProcs = @{} # PID -> AppName
$global:lastWifiSsid = $null            # NEW: WiFi SSID tracking
$global:lastPrinterJobs = @{}           # NEW: PrintJob ID -> doc name
$global:lastNetShareAlert = [DateTime]::MinValue  # NEW: net-share alert cooldown
$global:lastScreenLocked = $false       # NEW: screen lock state
$global:lastListeningPorts = @{}        # NEW: port number -> PID map
$global:lastScheduledTasks = @()        # NEW: task name list
$global:lastServices = @{}              # NEW: service name -> status map
$global:lastSoftware = @()              # NEW: installed software names
$global:lastWindowTitle = ""            # NEW: Track foreground window title
$global:batteryHistory = @()            # Fix: Properly initialize history array

# --- CONFIGURATION ---
$DEDUP_WINDOW_SEC = 3
$BATTERY_POLL_SEC = 5
$BATTERY_CRITICAL_DROP = 8 # Percent
$CPU_ALERT_THRESHOLD = 90
$CPU_COOLDOWN_SEC = 60

# ----------------- HELPER: LOGGING & SENDING -----------------
function Send-WatchtowerLog {
    param(
        [string]$eventType,      # Category: UserSession, AppBehaviour, SystemLifecycle, Security, DeviceControl, SystemPerformance
        [string]$userAction,     # Specific Action: PROCESS_START, USB_INSERTED, etc.
        [string]$appName,        # "chrome.exe", "System"
        [string]$severity,       # INFO, WARN, CRITICAL
        [hashtable]$extraData    # Extra details
    )

    # 1. DEDUPLICATION
    # Hash = EventType + AppName + UserAction
    $hashStr = "$eventType|$userAction|$appName"
    
    $now = Get-Date
    if ($global:lastSentHashes.ContainsKey($hashStr)) {
        $lastTime = $global:lastSentHashes[$hashStr]
        if (($now - $lastTime).TotalSeconds -lt $DEDUP_WINDOW_SEC) {
            # WRITE-HOST "DEBUG: Dropping duplicate $hashStr"
            return 
        }
    }
    $global:lastSentHashes[$hashStr] = $now
    
    # Cleanup old hashes occasionally
    if ($global:lastSentHashes.Count -gt 1000) { $global:lastSentHashes.Clear() }

    # 2. JSON CONSTRUCTION
    $meta = @{ hostname = $hostname }
    if ($extraData) {
        foreach ($k in $extraData.Keys) { $meta[$k] = $extraData[$k] }
    }

    $payload = @{
        event_type       = $eventType
        application_name = $appName
        user_action      = $userAction
        severity         = $severity
        source           = "WATCHTOWER_ELITE_AGENT"
        metadata         = $meta
    }
    
    # 3. SEND
    try {
        $json = $payload | ConvertTo-Json -Compress -Depth 5
        Invoke-RestMethod -Uri $serverUrl -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[SENT] $userAction - $appName ($severity)" -ForegroundColor Green
    }
    catch {
        Write-Host "[FAIL] Could not send log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ----------------- 1. PROCESS MONITORING (POLLING) -----------------
# Filter Rules
$sysNoise = @("svchost", "csrss", "smss", "wininit", "services", "lsass", "System", "Registry", "Memory Compression", "SearchApp", "RuntimeBroker", "taskhostw", "spoolsv", "postgres", "egui", "conhost", "node", "powershell", "pwsh")
$priorityApps = @("chrome", "msedge", "notepad", "notepad++", "code", "antigravity", "codeblocks", "excel", "winword")

# Maps a process name to the specific APP_LAUNCH_* or APP_STOP_* event type the dashboard expects
function Get-AppEventType {
    param([string]$pName, [bool]$isStop = $false)
    $prefix = if ($isStop) { "APP_STOP" } else { "APP_LAUNCH" }
    switch -Regex ($pName) {
        '(?i)^excel$'           { return "${prefix}_EXCEL" }
        '(?i)^winword$'         { return "${prefix}_WORD" }
        '(?i)^notepad\+\+$'    { return "${prefix}_NOTEPAD" }
        '(?i)^notepad$'         { return "${prefix}_NOTEPAD" }
        '(?i)^chrome$'          { return "${prefix}_CHROME" }
        '(?i)^msedge$'          { return "${prefix}_EDGE" }
        '(?i)^antigravity$'     { return "${prefix}_ANTIGRAVITY" }
        '(?i)^code$'            { return "${prefix}_VSCODE" }
        '(?i)^codeblocks$'      { return "${prefix}_CODEBLOCKS" }
        default                 { return "AppBehaviour" }
    }
}

$knownProcs = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $knownProcs[$_.Id] = $_.ProcessName }

function Invoke-ProcessMonitor {
    try {
        $currentProcsObjects = Get-Process -ErrorAction SilentlyContinue
        $currentProcs = @{}
        
        # We need a quick way to know which AppNames are currently tracked to only log first starts
        $currentlyTrackedApps = @{}
        foreach ($name in $global:trackedProcs.Values) {
            $currentlyTrackedApps[$name] = $true
        }

        foreach ($p in $currentProcsObjects) {
            $currentProcs[$p.Id] = $p.ProcessName
            
            # PROCESS START CHECK
            if ($knownProcs.Keys -notcontains $p.Id) {
                $pName = $p.ProcessName
                $pPath = ""
                try { $pPath = $p.Path } catch {} # Admin rights needed for some

                # --- FILTERING ---
                $isInteresting = $false
                
                # Rule 0: Priority Apps (We match regex to catch variations like winword, excel, msedge, antigravity)
                if ($pName -match "(?i)^(chrome|msedge|notepad|notepad\+\+|code|antigravity|codeblocks|excel|winword)$") {
                    $isInteresting = $true
                }
                else {
                    # Rule 1: Exclude Built-in Noise and Known Services
                    if ($sysNoise -contains $pName) { continue }
                    if ($pName -match "(?i)service|helper|update|notification|broker|host|background|daemon|agent|crash|report|telemetry|runner|installer|weather|wsmain") { continue }
                    
                    # Rule 2: Visual App (Title)
                    if ($p.MainWindowTitle.Length -gt 0) { 
                        $isInteresting = $true 
                    }
                    else {
                        # Rule 3: Path Whitelist for non-visual apps (strict)
                        if (($pPath -match "Program Files" -or $pPath -match "Users") -and $pPath -notmatch "AppData" -and $pPath -notmatch "Local\\Temp") {
                            $isInteresting = $true
                        }
                    }

                    # Rule 4: Exclude OS background processes
                    if ($pPath -match "^C:\\Windows\\" -or $pPath -match "WindowsApps" -or $pPath -match "SystemApps") { 
                        if ($pName -ne "explorer" -and $pName -ne "Taskmgr" -and $p.MainWindowTitle.Length -eq 0) {
                            $isInteresting = $false 
                        }
                    }
                }

                if ($isInteresting -and ($global:trackedProcs.Keys -notcontains $p.Id)) {
                    # Only log PROCESS_START if this is the FIRST instance of this application!
                    if (-not $currentlyTrackedApps.ContainsKey($pName)) {
                        $evtType = Get-AppEventType $pName $false
                        Send-WatchtowerLog $evtType "PROCESS_START" $pName "INFO" @{ 
                            path  = $pPath
                            pid   = $p.Id 
                            title = $p.MainWindowTitle
                        }
                        $currentlyTrackedApps[$pName] = $true # Mark as seen
                    }
                    $global:trackedProcs[$p.Id] = $pName
                }
            }
            else {
                # Ensure previously known processes are still tracked for PROCESS_STOP if they are interesting!
                if ($global:trackedProcs.Keys -notcontains $p.Id) {
                    $pName = $p.ProcessName
                    $pPath = ""
                    try { $pPath = $p.Path } catch {}

                    $isInteresting = $false
                    if ($pName -match "(?i)^(chrome|msedge|notepad|notepad\+\+|code|antigravity|codeblocks|excel|winword)$") {
                        $isInteresting = $true
                    }
                    elseif ($sysNoise -notcontains $pName -and $pName -notmatch "(?i)service|helper|update|notification|broker|host|background|daemon|agent|crash|report|telemetry|runner|installer|weather|wsmain") {
                        if ($p.MainWindowTitle.Length -gt 0) { $isInteresting = $true }
                        elseif (($pPath -match "Program Files" -or $pPath -match "Users") -and $pPath -notmatch "AppData" -and $pPath -notmatch "Local\\Temp") { $isInteresting = $true }
                        if ($pPath -match "^C:\\Windows\\" -or $pPath -match "WindowsApps" -or $pPath -match "SystemApps") { 
                            if ($pName -ne "explorer" -and $pName -ne "Taskmgr" -and $p.MainWindowTitle.Length -eq 0) { $isInteresting = $false }
                        }
                    }
                    
                    if ($isInteresting) {
                        if (-not $currentlyTrackedApps.ContainsKey($pName)) {
                            $evtType = Get-AppEventType $pName $false
                            Send-WatchtowerLog $evtType "PROCESS_START" $pName "INFO" @{ 
                                path  = $pPath
                                pid   = $p.Id 
                                title = $p.MainWindowTitle
                            }
                            $currentlyTrackedApps[$pName] = $true
                        }
                        $global:trackedProcs[$p.Id] = $pName
                    }
                }
            }
        }

        # Update knownProcs list so we don't repeat this
        $script:knownProcs = $currentProcs

        # PROCESS STOP CHECK
        $stoppedPids = @()
        foreach ($pidTracked in $global:trackedProcs.Keys) {
            if ($currentProcs.Keys -notcontains $pidTracked) {
                $stoppedPids += $pidTracked
            }
        }
        
        # Only log PROCESS_STOP if this was the LAST instance of the application!
        foreach ($pidStopped in $stoppedPids) {
            $stoppedAppName = $global:trackedProcs[$pidStopped]
            $global:trackedProcs.Remove($pidStopped)
            
            # Check if any OTHER instance of this app remains
            $instancesRemaining = 0
            foreach ($remainingAppName in $global:trackedProcs.Values) {
                if ($remainingAppName -eq $stoppedAppName) {
                    $instancesRemaining++
                    break
                }
            }
            
            if ($instancesRemaining -eq 0) {
                # This was the very last instance of the application, valid stop log
                $evtType = Get-AppEventType $stoppedAppName $true
                Send-WatchtowerLog $evtType "PROCESS_STOP" $stoppedAppName "INFO" @{
                    pid = $pidStopped
                }
            }
        }

        return $currentProcs
    }
    catch {
        Write-Host "Error in ProcessMonitor: $($_.Exception.Message)" -ForegroundColor Yellow
        return $knownProcs
    }
}

# ----------------- 2. RESOURCE MONITORING (CPU/RAM) -----------------
function Invoke-ResourceMonitor {
    # CPU Load
    $cpu = (Get-CimInstance Win32_Processor).LoadPercentage
    
    # Track History (Last 3 samples)
    $global:cpuHistory += $cpu
    if ($global:cpuHistory.Count -gt 3) { $global:cpuHistory = $global:cpuHistory | Select-Object -Last 3 }
    
    # Calculate Average
    $avgCpu = ($global:cpuHistory | Measure-Object -Average).Average

    # High CPU Check
    if ($avgCpu -ge $CPU_ALERT_THRESHOLD) {
        $now = Get-Date
        if (($now - $global:lastHighCpuAlert).TotalSeconds -ge $CPU_COOLDOWN_SEC) {
            
            # Get Top 3 Consumers
            $topProcs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 3
            
            $consumerData = @()
            foreach ($proc in $topProcs) {
                $consumerData += @{ Name = $proc.ProcessName; ID = $proc.Id; CPU = [Math]::Round($proc.CPU, 1) }
            }

            Send-WatchtowerLog "SystemPerformance" "HIGH_CPU_LOAD" "System" "WARN" @{
                current_load  = $avgCpu
                threshold     = $CPU_ALERT_THRESHOLD
                top_consumers = $consumerData
            }
            $global:lastHighCpuAlert = $now
        }
    }
}

# ----------------- 3. DEVICE MONITORING (USB, BT, AIRPLANE) -----------------
function Invoke-DeviceMonitor {
    try {
        # --- A. USB STORAGE DETECTION ---
        $currentDrives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Removable' } | Select-Object -ExpandProperty Name
        
        # Detect Insertion
        foreach ($drive in $currentDrives) {
            if ($global:lastUsbDrives -notcontains $drive) {
                $volInfo = [System.IO.DriveInfo]::new($drive)
                
                Send-WatchtowerLog "DeviceControl" "USB_STORAGE_INSERTED" "System" "INFO" @{
                    drive_letter = $drive
                    label        = $volInfo.VolumeLabel
                    capacity_gb  = [Math]::Round($volInfo.TotalSize / 1GB, 2)
                }
            }
        }

        # Detect Removal
        foreach ($oldDrive in $global:lastUsbDrives) {
            if ($currentDrives -notcontains $oldDrive) {
                Send-WatchtowerLog "DeviceControl" "USB_STORAGE_REMOVED" "System" "INFO" @{ drive_letter = $oldDrive }
            }
        }
        $global:lastUsbDrives = $currentDrives

        # --- A.2. MOBILE PHONE & GENERIC USB DETECTION ---
        if ($null -eq $global:lastUsbDevices) { $global:lastUsbDevices = @() }

        # Grab all USB entities instead of just WPD (File Transfer) to catch charge-only phones
        $currentUsbObjs = Get-CimInstance Win32_PnPEntity -Filter "DeviceID LIKE 'USB%'" -ErrorAction SilentlyContinue 
        $currentUsbList = @()
        if ($currentUsbObjs) {
            foreach ($p in $currentUsbObjs) { 
                if ($p.Name) { $currentUsbList += $p.Name } 
            }
        }

        # Detect Phone/USB Connection
        foreach ($usb in $currentUsbList) {
            if ($global:lastUsbDevices -notcontains $usb) {
                # Ignore root hubs to reduce noise
                if ($usb -notmatch "Root Hub|Composite Device|Host Controller") {
                    Send-WatchtowerLog "DeviceControl" "MOBILE_PHONE_CONNECTED" "System" "INFO" @{
                        device_name = $usb
                        message = "USB Device / Phone plugged in: $usb"
                    }
                }
            }
        }

        # Detect Phone/USB Disconnection
        foreach ($oldUsb in $global:lastUsbDevices) {
            if ($currentUsbList -notcontains $oldUsb) {
                if ($oldUsb -notmatch "Root Hub|Composite Device|Host Controller") {
                    Send-WatchtowerLog "DeviceControl" "MOBILE_PHONE_DISCONNECTED" "System" "INFO" @{
                        device_name = $oldUsb
                        message = "USB Device / Phone removed: $oldUsb"
                    }
                }
            }
        }
        $global:lastUsbDevices = $currentUsbList


        # --- B. BLUETOOTH STATUS (Service) ---
        $btService = Get-Service -Name bthserv -ErrorAction SilentlyContinue
        
        $currentBtStatus = "UNKNOWN"
        if ($btService -and $btService.Status -eq 'Running') { $currentBtStatus = "ON" } 
        elseif ($btService) { $currentBtStatus = "OFF" }

        if ($null -ne $global:lastBluetoothStatus -and $currentBtStatus -ne $global:lastBluetoothStatus -and $currentBtStatus -ne "UNKNOWN") {
            Send-WatchtowerLog "DeviceControl" "BLUETOOTH_STATE_CHANGE" "System" "INFO" @{
                status = $currentBtStatus
            }
        }
        $global:lastBluetoothStatus = $currentBtStatus


        # --- C. AIRPLANE MODE (Registry) ---
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\RadioManagement\SystemRadioState"
        
        try {
            $val = Get-ItemProperty -Path $regPath -Name "(default)" -ErrorAction SilentlyContinue 
            # 1=Airplane ON, 0=OFF
            
            $currentRadio = "UNKNOWN"
            if ($val) {
                if ($val.'(default)' -eq 1) { $currentRadio = "AIRPLANE_MODE_ON" }
                else { $currentRadio = "AIRPLANE_MODE_OFF" }
            }

            if ($null -ne $global:lastRadioState -and $currentRadio -ne $global:lastRadioState -and $currentRadio -ne "UNKNOWN") {
                Send-WatchtowerLog "DeviceControl" $currentRadio "System" "INFO" @{
                    registry_path = $regPath
                }
            }
            $global:lastRadioState = $currentRadio

        }
        catch {}
    }
    catch {
        Write-Host "Error in DeviceMonitor: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}


# ----------------- 4. WIFI MONITORING -----------------
function Invoke-WifiMonitor {
    try {
        # Use netsh to get current connected SSID (works without admin)
        $netshOut = netsh wlan show interfaces 2>$null
        $ssidLine = $netshOut | Where-Object { $_ -match '\bSSID\b\s*:' } | Select-Object -First 1
        $currentSsid = if ($ssidLine) { ($ssidLine -split ':', 2)[1].Trim() } else { $null }

        if ($currentSsid -ne $global:lastWifiSsid) {
            if ($null -ne $currentSsid -and $currentSsid -ne '') {
                Send-WatchtowerLog "Network" "WIFI_CONNECTED" "System" "INFO" @{
                    ssid    = $currentSsid
                    message = "Connected to WiFi network: $currentSsid"
                }
            } elseif ($null -ne $global:lastWifiSsid -and $global:lastWifiSsid -ne '') {
                Send-WatchtowerLog "Network" "WIFI_DISCONNECTED" "System" "INFO" @{
                    ssid    = $global:lastWifiSsid
                    message = "Disconnected from WiFi network: $($global:lastWifiSsid)"
                }
            }
            $global:lastWifiSsid = $currentSsid
        }
    }
    catch {
        Write-Host "Error in WifiMonitor: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ----------------- 5. PRINTER MONITORING -----------------
function Invoke-PrinterMonitor {
    try {
        $printJobs = Get-Printer -ErrorAction SilentlyContinue | Get-PrintJob -ErrorAction SilentlyContinue
        if (-not $printJobs) { return }
        foreach ($job in $printJobs) {
            $jobId = $job.Id
            if (-not $global:lastPrinterJobs.ContainsKey($jobId)) {
                Send-WatchtowerLog "PrintService" "DOCUMENT_PRINTED" $job.PrinterName "INFO" @{
                    document_name = $job.DocumentName
                    job_id        = $jobId
                    pages         = $job.TotalPages
                    submitted_by  = $job.UserName
                }
                $global:lastPrinterJobs[$jobId] = $job.DocumentName
            }
        }
        # Prune completed jobs from our tracker
        $activeIds = $printJobs | ForEach-Object { $_.Id }
        $keysToRemove = @($global:lastPrinterJobs.Keys | Where-Object { $activeIds -notcontains $_ })
        foreach ($k in $keysToRemove) { $global:lastPrinterJobs.Remove($k) }
    }
    catch {
        Write-Host "Error in PrinterMonitor: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ----------------- 6. BATTERY MONITORING -----------------
function Invoke-BatteryMonitor {
    $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if (-not $bat) { return }

    $level = $bat.EstimatedChargeRemaining
    $status = $bat.BatteryStatus # 1=Discharging, 2=AC
    $now = Get-Date

    # Store history
    $global:batteryHistory += @{ Time = $now; Level = $level; Status = $status }
    
    # Prune old history (> 15 mins)
    $global:batteryHistory = @($global:batteryHistory | Where-Object { ($now - $_.Time).TotalMinutes -le 15 })

    # CHECK DRAIN (Compare with entry ~10 mins ago)
    $oldEntry = $global:batteryHistory | Where-Object { ($now - $_.Time).TotalMinutes -ge 9 } | Sort-Object Time | Select-Object -Last 1
    
    if ($oldEntry) {
        $drop = $oldEntry.Level - $level
        if ($drop -ge $BATTERY_CRITICAL_DROP -and $status -eq 1) {
            Send-WatchtowerLog "SystemLifecycle" "BATTERY_DRAIN" "System" "CRITICAL" @{
                drop_percent    = $drop
                time_window_min = 10
                current_level   = $level
                message         = "Rapid battery drain detected."
            }
            $global:batteryHistory = @()
        }
    }
}

# ----------------- 7. LISTENING PORT MONITOR -----------------
function Invoke-PortMonitor {
    try {
        $currentPorts = @{}
        $connections = netstat -ano 2>$null | Select-String 'LISTENING'
        foreach ($line in $connections) {
            if ($line -match '\s+(\d+\.\d+\.\d+\.\d+|\[::.*\]):(\d+)\s+.*LISTENING\s+(\d+)') {
                $port = [int]$Matches[2]; $pid_ = $Matches[3]
                $currentPorts[$port] = $pid_
            }
        }
        if ($global:lastListeningPorts.Count -gt 0) {
            foreach ($port in $currentPorts.Keys) {
                if (-not $global:lastListeningPorts.ContainsKey($port)) {
                    $pid_ = $currentPorts[$port]
                    $procName = try { (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
                    Send-WatchtowerLog "Network" "NETWORK_PORT_OPENED" "System" "MEDIUM" @{
                        port = $port; pid = $pid_; process = $procName
                        message = "New listening port: $port ($procName)"
                    }
                }
            }
            foreach ($port in $global:lastListeningPorts.Keys) {
                if (-not $currentPorts.ContainsKey($port)) {
                    Send-WatchtowerLog "Network" "NETWORK_PORT_CLOSED" "System" "INFO" @{
                        port = $port; message = "Port closed: $port"
                    }
                }
            }
        }
        $global:lastListeningPorts = $currentPorts
    }
    catch { Write-Host "Error in PortMonitor: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ----------------- 8. SCHEDULED TASK MONITOR -----------------
function Invoke-ScheduledTaskMonitor {
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $_.TaskName })
        if ($global:lastScheduledTasks.Count -eq 0) { $global:lastScheduledTasks = $tasks; return }
        $newTasks = $tasks | Where-Object { $global:lastScheduledTasks -notcontains $_ }
        foreach ($task in $newTasks) {
            Send-WatchtowerLog "Persistence" "SCHEDULED_TASK_CREATED" "TaskScheduler" "HIGH" @{
                task_name = $task; message = "New scheduled task detected: $task"
            }
        }
        $global:lastScheduledTasks = $tasks
    }
    catch { Write-Host "Error in ScheduledTaskMonitor: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ----------------- 9. SERVICE MONITOR -----------------
function Invoke-ServiceMonitor {
    try {
        $currentServices = @{}
        Get-Service -ErrorAction SilentlyContinue | ForEach-Object { $currentServices[$_.Name] = "$($_.Status)" }
        if ($global:lastServices.Count -eq 0) { $global:lastServices = $currentServices; return }
        foreach ($name in $currentServices.Keys) {
            if (-not $global:lastServices.ContainsKey($name)) {
                Send-WatchtowerLog "Persistence" "NEW_SERVICE_DETECTED" "ServiceControl" "HIGH" @{
                    service_name = $name; status = $currentServices[$name]
                    message = "New service discovered: $name ($($currentServices[$name]))"
                }
            }
        }
        $global:lastServices = $currentServices
    }
    catch { Write-Host "Error in ServiceMonitor: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ----------------- 10. SOFTWARE INSTALL MONITOR -----------------
function Invoke-SoftwareMonitor {
    try {
        $regPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $currentSoftware = @()
        foreach ($path in $regPaths) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object { $currentSoftware += $_.DisplayName }
        }
        if ($global:lastSoftware.Count -eq 0) { $global:lastSoftware = $currentSoftware; return }
        $installed   = @($currentSoftware | Where-Object { $global:lastSoftware -notcontains $_ })
        $uninstalled = @($global:lastSoftware  | Where-Object { $currentSoftware -notcontains $_ })
        foreach ($app in $installed)   { Send-WatchtowerLog "SoftwareManagement" "SOFTWARE_INSTALLED"   "System" "MEDIUM" @{ software = $app; message = "Software installed: $app" } }
        foreach ($app in $uninstalled) { Send-WatchtowerLog "SoftwareManagement" "SOFTWARE_UNINSTALLED" "System" "INFO"   @{ software = $app; message = "Software uninstalled: $app" } }
        $global:lastSoftware = $currentSoftware
    }
    catch { Write-Host "Error in SoftwareMonitor: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ----------------- 5. EVENT LOG WATCHER -----------------
# (Keeping existing Event Log logic mostly same, just ensuring correct types)
$win32EventsType = @'
using System;
using System.Diagnostics.Eventing.Reader;
public class Win32Events {
    public static string GetEventLogMessage(EventRecord eventRecord) {
        try { return eventRecord.FormatDescription() ?? ""; }
        catch { return ""; }
    }
}
'@
Add-Type -TypeDefinition $win32EventsType -ErrorAction SilentlyContinue

# --- NEW: ACTIVE WINDOW MONITOR (Win32 API) ---
$windowApi = @'
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    public class WindowApi {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    }
'@
Add-Type -TypeDefinition $windowApi -ErrorAction SilentlyContinue

function Invoke-ActiveWindowMonitor {
    try {
        $hWnd = [WindowApi]::GetForegroundWindow()
        if ($hWnd -ne [IntPtr]::Zero) {
            $sb = New-Object System.Text.StringBuilder 256
            [WindowApi]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
            $currentTitle = $sb.ToString()

            if ($null -ne $currentTitle -and $currentTitle -ne "" -and $currentTitle -ne $global:lastWindowTitle) {
                Send-WatchtowerLog "AppBehaviour" "FOREGROUND_WINDOW_CHANGE" "System" "INFO" @{
                    title      = $currentTitle
                    prev_title = $global:lastWindowTitle
                }
                $global:lastWindowTitle = $currentTitle
                Write-Host "[FOCUS] -> $currentTitle" -ForegroundColor Cyan
            }
        }
    } catch {
        # Silent fail for window polling
    }
}

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

function Take-Screenshot {
    try {
        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $bytes = $ms.ToArray()
        $base64 = [Convert]::ToBase64String($bytes)
        
        $graphics.Dispose()
        $bmp.Dispose()
        $ms.Dispose()
        return "data:image/jpeg;base64,$base64"
    } catch { 
        return $null 
    }
}

function Initialize-EventWatcher {
    # Security: failed login + successful login + logoff + screen lock + net share
    $querySec = "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4800 or EventID=4801 or EventID=5140)]]"
    $watcherSec = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher(
        (New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Security", [System.Diagnostics.Eventing.Reader.PathType]::LogName, $querySec))
    )

    $querySys = "*[System[(EventID=1074 or EventID=6005 or EventID=6006 or EventID=41 or EventID=42 or EventID=1)]]"
    $watcherSys = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher(
        (New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("System", [System.Diagnostics.Eventing.Reader.PathType]::LogName, $querySys))
    )

    $action = {
        $e = $Event.SourceEventArgs.EventRecord
        $id = $e.Id
        $msg = [Win32Events]::GetEventLogMessage($e)

        # --- SECURITY EVENTS ---
        if ($id -eq 4624) {
            # Successful Login (filter out noisy logon types 3=network, 5=service, 4=batch)
            try {
                $logonType = $e.Properties[8].Value  # LogonType field
                if ($logonType -eq 2 -or $logonType -eq 10 -or $logonType -eq 11) {
                    # 2=Interactive, 10=RemoteInteractive, 11=CachedInteractive
                    $username = $e.Properties[5].Value
                    Send-WatchtowerLog "Authentication" "LOGIN_SUCCESS" "SecuritySubsystem" "INFO" @{
                        username   = $username
                        logon_type = $logonType
                        message    = "Interactive login: $username"
                    }
                }
            } catch {}
        }
        elseif ($id -eq 4625) {
            # Failed Login
            try {
                $username = $e.Properties[5].Value
                Send-WatchtowerLog "Authentication" "LOGIN_FAILED" "SecuritySubsystem" "WARN" @{
                    username = $username
                    message  = "Failed login attempt for: $username"
                }
            } catch {
                Send-WatchtowerLog "Authentication" "LOGIN_FAILED" "SecuritySubsystem" "WARN" @{ message = $msg }
            }
        }
        elseif ($id -eq 4634 -or $id -eq 4647) {
            # User Logoff
            try {
                $username = $e.Properties[1].Value
                Send-WatchtowerLog "Authentication" "USER_LOGOFF" "SecuritySubsystem" "INFO" @{
                    username = $username
                    event_id = $id
                }
            } catch {
                Send-WatchtowerLog "Authentication" "USER_LOGOFF" "SecuritySubsystem" "INFO" @{ message = $msg }
            }
        }
        elseif ($id -eq 4800) {
            # Workstation Locked
            try {
                $username = $e.Properties[1].Value
                Send-WatchtowerLog "Authentication" "SCREEN_LOCKED" "SecuritySubsystem" "INFO" @{
                    username = $username
                    message  = "Workstation locked by: $username"
                }
            } catch {
                Send-WatchtowerLog "Authentication" "SCREEN_LOCKED" "SecuritySubsystem" "INFO" @{ message = $msg }
            }
        }
        elseif ($id -eq 4801) {
            # Workstation Unlocked
            try {
                $username = $e.Properties[1].Value
                Send-WatchtowerLog "Authentication" "SCREEN_UNLOCKED" "SecuritySubsystem" "INFO" @{
                    username = $username
                    message  = "Workstation unlocked by: $username"
                }
            } catch {
                Send-WatchtowerLog "Authentication" "SCREEN_UNLOCKED" "SecuritySubsystem" "INFO" @{ message = $msg }
            }
        }
        elseif ($id -eq 5140) {
            # Network Share Access
            try {
                $username  = $e.Properties[1].Value
                $shareName = $e.Properties[7].Value
                $srcIp     = $e.Properties[3].Value
                Send-WatchtowerLog "FileShare" "SHARE_ACCESS" "SecuritySubsystem" "INFO" @{
                    username   = $username
                    share_name = $shareName
                    source_ip  = $srcIp
                    message    = "$username accessed share '$shareName' from $srcIp"
                }
            } catch {}
        }
        # --- SYSTEM EVENTS ---
        elseif ($id -eq 1074) { Send-WatchtowerLog "SystemLifecycle" "SHUTDOWN_INITIATED" "System" "INFO" @{ message = "System shutdown or restart initiated." } }
        elseif ($id -eq 6005) { Send-WatchtowerLog "SystemLifecycle" "SYSTEM_STARTUP"     "System" "INFO" @{ message = "Event Log service started (System booted)." } }
        elseif ($id -eq 6006) { Send-WatchtowerLog "SystemLifecycle" "SYSTEM_SHUTDOWN"    "System" "INFO" @{ message = "Event Log service stopped (System shutting down)." } }
        elseif ($id -eq 42)   { Send-WatchtowerLog "SystemLifecycle" "SYSTEM_SLEEP"       "System" "INFO" @{ message = "The system is entering sleep/hibernate." } }
        elseif ($id -eq 1)    { Send-WatchtowerLog "SystemLifecycle" "SYSTEM_WAKE"        "System" "INFO" @{ message = "The system has resumed from sleep." } }
    }
    
    Register-ObjectEvent -InputObject $watcherSec -EventName "EventRecordWritten" -SourceIdentifier "SecWatcher" -Action $action | Out-Null
    Register-ObjectEvent -InputObject $watcherSys -EventName "EventRecordWritten" -SourceIdentifier "SysWatcher" -Action $action | Out-Null
    # --- NEW: AC POWER STATUS WATCHER (WMI) ---
    $queryPower = "SELECT * FROM Win32_PowerManagementEvent"
    $actionPower = {
        $eventType = $Event.SourceEventArgs.NewEvent.EventType
        # 10 = AC power status changed
        if ($eventType -eq 10) {
            $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
            if ($bat) {
                if ($bat.BatteryStatus -eq 2) {
                    Send-WatchtowerLog "SystemLifecycle" "CHARGER_PLUGGED_IN" "System" "INFO" @{ level = $bat.EstimatedChargeRemaining }
                }
                elseif ($bat.BatteryStatus -eq 1) {
                    Send-WatchtowerLog "SystemLifecycle" "CHARGER_UNPLUGGED" "System" "INFO" @{ level = $bat.EstimatedChargeRemaining }
                }
            }
        }
    }
    Register-WmiEvent -Query $queryPower -SourceIdentifier "PowerWatcher" -Action $actionPower | Out-Null

    # --- NEW: APPLICATION EVENTS WATCHER WITH SCREENSHOTS ---
    $queryApp = "*[System[Level=2]]" # Level 2 = Error
    $watcherApp = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher(
        (New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Application", [System.Diagnostics.Eventing.Reader.PathType]::LogName, $queryApp))
    )
    $actionApp = {
        $e = $Event.SourceEventArgs.EventRecord
        $id = $e.Id
        $msg = [Win32Events]::GetEventLogMessage($e)
        $provider = $e.ProviderName
        
        # When an application error occurs, grab a screenshot!
        $b64 = Take-Screenshot
        
        Send-WatchtowerLog "AppBehaviour" "APPLICATION_ERROR" $provider "WARN" @{
            event_id = $id
            message  = $msg
            screenshot = $b64
        }
    }
    Register-ObjectEvent -InputObject $watcherApp -EventName "EventRecordWritten" -SourceIdentifier "AppWatcher" -Action $actionApp | Out-Null

    $watcherSec.Enabled = $true
    $watcherSys.Enabled = $true
    $watcherApp.Enabled = $true
}

# ----------------- 11. COMMAND POLLER (ACTIVE RESPONSE) -----------------
function Invoke-CommandPoller {
    try {
        $pollUrl = "$($serverUrl.Replace('/log', '/poll'))/$hostname"
        $response = Invoke-RestMethod -Uri $pollUrl -Method Get -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.commands -and $response.commands.Count -gt 0) {
            foreach ($cmd in $response.commands) {
                Write-Host "[REMOTE] Received Command: $($cmd.command)" -ForegroundColor Cyan
                $status = "SUCCESS"
                $details = @{ command = $cmd.command }
                
                try {
                    switch ($cmd.command) {
                        "LOCK" {
                            Write-Host "[ACTION] Locking workstation..." -ForegroundColor Yellow
                            $process = Start-Process "rundll32.exe" -ArgumentList "user32.dll,LockWorkStation" -PassThru
                            $details.message = "Workstation locked successfully"
                        }
                        "KILL_PROC" {
                            $pidToKill = $cmd.params.pid
                            $pName = $cmd.params.name
                            Write-Host "[ACTION] Terminating process: $pName (PID: $pidToKill)" -ForegroundColor Red
                            if ($pidToKill) {
                                Stop-Process -Id $pidToKill -Force -ErrorAction Stop
                                $details.message = "Process $pidToKill ($pName) terminated"
                            } else { throw "Missing PID" }
                        }
                        "MSG" {
                            $msgText = if ($cmd.params.text) { $cmd.params.text } else { "Security Alert from SOC" }
                            $msgTitle = if ($cmd.params.title) { $cmd.params.title } else { "SIEM Watchtower" }
                            Write-Host "[ACTION] Displaying message: $msgText" -ForegroundColor Yellow
                            $ws = New-Object -ComObject WScript.Shell
                            $ws.Popup($msgText, 10, $msgTitle, 48) # 10s timeout, Warning icon
                            $details.message = "Message displayed"
                        }
                        default {
                            $status = "FAILED"
                            $details.message = "Unknown command: $($cmd.command)"
                        }
                    }
                }
                catch {
                    $status = "FAILED"
                    $details.message = $_.Exception.Message
                    Write-Host "[ERROR] Command failed: $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Report Result back to SOC
                try {
                    $resultUrl = $serverUrl.Replace('/log', '/command-result')
                    $resPayload = @{
                        hostname  = $hostname
                        commandId = $cmd.id
                        status    = $status
                        details   = $details
                    }
                    $json = $resPayload | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $resultUrl -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5
                } catch {}
            }
        }
    }
    catch {
        # Silent fail for poll (server might be down)
    }
}


# ----------------- MAIN LOOP -----------------

Write-Host "Starting WATCHTOWER ELITE AGENT v5.0..." -ForegroundColor Cyan

try { Initialize-EventWatcher } catch { Write-Host "Checking EventLog requires Admin!" -ForegroundColor Yellow }

$timerBattery  = [System.Diagnostics.Stopwatch]::StartNew()
$timerResource = [System.Diagnostics.Stopwatch]::StartNew()
$timerWifi     = [System.Diagnostics.Stopwatch]::StartNew()
$timerPrinter  = [System.Diagnostics.Stopwatch]::StartNew()
$timerPort     = [System.Diagnostics.Stopwatch]::StartNew()
$timerTask     = [System.Diagnostics.Stopwatch]::StartNew()
$timerService  = [System.Diagnostics.Stopwatch]::StartNew()
$timerSoftware = [System.Diagnostics.Stopwatch]::StartNew()
$timerPoll     = [System.Diagnostics.Stopwatch]::StartNew()

while ($true) {
    try {
        # 1. Process Polling (Every 3s)
        $knownProcs = Invoke-ProcessMonitor

        # 1.1 Active Window Polling (Every 3s)
        Invoke-ActiveWindowMonitor

        # 2. Device Polling (Every 3s)
        Invoke-DeviceMonitor

        # 3. Resource Polling (Every 5s for avg calc)
        if ($timerResource.Elapsed.TotalSeconds -ge 5) {
            Invoke-ResourceMonitor
            $timerResource.Restart()
        }

        # 4. Battery Polling (Every 5s)
        if ($timerBattery.Elapsed.TotalSeconds -ge $BATTERY_POLL_SEC) {
            Invoke-BatteryMonitor
            $timerBattery.Restart()
        }

        # 5. WiFi Polling (Every 10s — netsh is slow)
        if ($timerWifi.Elapsed.TotalSeconds -ge 10) {
            Invoke-WifiMonitor
            $timerWifi.Restart()
        }

        # 6. Printer Polling (Every 5s)
        if ($timerPrinter.Elapsed.TotalSeconds -ge 5) {
            Invoke-PrinterMonitor
            $timerPrinter.Restart()
        }

        # 7. Port Monitor (Every 30s)
        if ($timerPort.Elapsed.TotalSeconds -ge 30) {
            Invoke-PortMonitor
            $timerPort.Restart()
        }

        # 8. Scheduled Task Monitor (Every 60s)
        if ($timerTask.Elapsed.TotalSeconds -ge 60) {
            Invoke-ScheduledTaskMonitor
            $timerTask.Restart()
        }

        # 9. Service Monitor (Every 30s)
        if ($timerService.Elapsed.TotalSeconds -ge 30) {
            Invoke-ServiceMonitor
            $timerService.Restart()
        }

        # 10. Software Install Monitor (Every 120s)
        if ($timerSoftware.Elapsed.TotalSeconds -ge 120) {
            Invoke-SoftwareMonitor
            $timerSoftware.Restart()
        }

        # 11. Command Poller (Every 10s)
        if ($timerPoll.Elapsed.TotalSeconds -ge 10) {
            Invoke-CommandPoller
            $timerPoll.Restart()
        }

    }
    catch {
        Write-Host "Error in Main Loop: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}
