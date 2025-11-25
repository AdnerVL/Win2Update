#Requires -Version 7.0
#Requires -RunAsAdministrator

# ============================================
# SYNOPSIS: Automates remote Windows updates and app upgrades using Microsoft-developed tools (Windows Update service + winget for non-Store apps).
# References: Winget install/usage from [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/package-manager/winget/); Upgrade command from [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade); Limitations for Store apps from [github.com](https://github.com/microsoft/winget-cli/issues/2854); SYSTEM context fixes from [community.spiceworks.com](https://community.spiceworks.com/t/winget-fails-to-upgrade-apps-when-run-as-system/1058983).
# ============================================

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$HostName,
    
    [Parameter(Position=1)]
    [string]$HostsFile = (Join-Path $PSScriptRoot 'hosts.txt'),
    
    [Parameter(Position=2)]
    [string]$YamlFile = (Join-Path $PSScriptRoot 'hosts_tracking.yaml'),
    
    [Parameter(Position=3)]
    [string]$QueueFile = (Join-Path $PSScriptRoot 'hostQueue.txt'),
    
    [Parameter(Position=4)]
    [ValidateRange(0, 365)]
    [int]$SkipDays = 5,
    
    [Parameter(Position=5)]
    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 10,
    
    [ValidateRange(0, 86400)]
    [int]$QueueDuration = 3600,
    
    [Parameter(Position=6)]
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$script:QueueDuration = $QueueDuration
$script:PSScriptRoot = $PSScriptRoot  # Preserve for use in parallel blocks

# ============================================
# THREAD-SAFE LOGGING
# ============================================

# Initialize LogLock as a global object that can be safely used across parallel contexts
if (-not $script:LogLock) {
    $script:LogLock = [System.Threading.Mutex]::new($false, "UpdateScriptLogMutex")
}

function Write-Log {
    param(
        [string]$Message,
        [string]$RemoteHost = "",
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',
        [string]$ScriptRoot = $null
    )
    
    $colors = @{
        'Error' = 'Red'
        'Warning' = 'Yellow'
        'Success' = 'Green'
        'Info' = 'White'
    }
    
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $logMessage = "[$timestamp] [$Level]"
    if ($RemoteHost) { $logMessage += " [$RemoteHost]" }
    $logMessage += " $Message"
    
    # Handle both global LogLock and function-local context
    if ($script:LogLock) {
        $null = $script:LogLock.WaitOne()
    }
    try {
        Write-Host $logMessage -ForegroundColor $colors[$Level]
        $root = if ($ScriptRoot) { $ScriptRoot } else { $script:PSScriptRoot }
        if ($root) {
            $logFile = Join-Path $root ".logs\update_script.log"
            if ($logFile) {
                $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        if ($script:LogLock) {
            $script:LogLock.ReleaseMutex()
        }
    }
}

# ============================================
# YAML HANDLING (unchanged)
# ============================================

function ConvertFrom-SimpleYaml {
    param([string]$Content)
    
    $data = @{ systems = @() }
    if ([string]::IsNullOrWhiteSpace($Content)) { return $data }
    
    $currentSystem = $null
    foreach ($line in ($Content -split '\r?\n' | Where-Object { $_ -match '\S' })) {
        switch -Regex ($line) {
            '^-\s*hostname:\s*(.+)$' {
                if ($currentSystem) { $data.systems += $currentSystem }
                $currentSystem = @{
                    hostname = $matches[1].Trim()
                    last_connection_timestamp = $null
                    last_successful_update_timestamp = $null
                    update_success = $false
                }
            }
            '^\s*(last_connection_timestamp|last_successful_update_timestamp):\s*(.+)$' {
                if ($currentSystem) { $currentSystem[$matches[1]] = $matches[2].Trim() }
            }
            '^\s*update_success:\s*(true|false)$' {
                if ($currentSystem) { $currentSystem.update_success = $matches[1] -eq 'true' }
            }
        }
    }
    if ($currentSystem) { $data.systems += $currentSystem }
    return $data
}

function ConvertTo-SimpleYaml {
    param([hashtable]$Data)
    
    $yaml = "systems:`n"
    foreach ($system in $Data.systems) {
        $yaml += @"
- hostname: $($system.hostname)
  last_connection_timestamp: $(if ($system.last_connection_timestamp) { $system.last_connection_timestamp } else { '' })
  last_successful_update_timestamp: $(if ($system.last_successful_update_timestamp) { $system.last_successful_update_timestamp } else { '' })
  update_success: $($system.update_success.ToString().ToLower())

"@
    }
    return $yaml
}

function Load-YamlData {
    param([string]$File)
    
    if (-not (Test-Path $File)) {
        $data = @{ systems = @() }
        Save-YamlData -Data $data -File $File
        return $data
    }
    
    $content = Get-Content -Path $File -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    return ConvertFrom-SimpleYaml -Content $content
}

function Save-YamlData {
    param(
        [hashtable]$Data,
        [string]$File
    )
    
    if (-not $Data) { return }
    $yaml = ConvertTo-SimpleYaml -Data $Data
    $yaml | Set-Content -Path $File -Encoding UTF8 -Force
}

# ============================================
# QUEUE MANAGEMENT (unchanged)
# ============================================

function Get-HostQueue {
    param([string]$File)
    
    $queue = @{}
    if (-not (Test-Path $File)) { return $queue }
    
    try {
        Get-Content $File -Encoding UTF8 -ErrorAction Stop | ForEach-Object {
            if ($_) {
                $parts = $_ -split ','
                if ($parts.Length -ge 2) {
                    $hostname = $parts[0].Trim()
                    try {
                        $queue[$hostname] = [datetime]::Parse($parts[1])
                    } catch {
                        Write-Log -Level Warning -Message "Invalid timestamp for $hostname"
                    }
                }
            }
        }
    } catch {
        Write-Log -Level Warning -Message "Error reading queue file: $_"
    }
    
    $now = Get-Date
    $keysToRemove = $queue.Keys | Where-Object { 
        ($now - $queue[$_]).TotalSeconds -gt $script:QueueDuration 
    }
    foreach ($k in $keysToRemove) { $queue.Remove($k) }
    
    return $queue
}

function Save-HostQueue {
    param(
        [hashtable]$Queue,
        [string]$File
    )
    
    if ($null -eq $Queue) { return }
    
    $lines = $Queue.GetEnumerator() | 
        Where-Object { $_.Value } | 
        ForEach-Object { "$($_.Key),$($_.Value.ToString('o'))" }
    
    if ($lines) {
        $lines | Out-File -FilePath $File -Encoding UTF8 -Force
    } else {
        Clear-Content -Path $File -ErrorAction SilentlyContinue
    }
}

# ============================================
# HOST MANAGEMENT (unchanged)
# ============================================

function Get-TargetHosts {
    param([string]$File)
    
    if (-not (Test-Path $File)) {
        Write-Log -Level Warning -Message "Hosts file not found: $File"
        return @()
    }
    
    $hosts = Get-Content $File -Encoding UTF8 -ErrorAction SilentlyContinue | 
        Where-Object { $_ -and $_ -match '^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$' } |
        ForEach-Object { $_.Trim() }
    
    Write-Log -Message "Found $($hosts.Count) valid hosts"
    return $hosts
}

function Should-ProcessHost {
    param(
        [string]$RemoteHost,
        [hashtable]$Queue,
        [int]$Duration,
        [bool]$Force
    )
    
    if ($Force) { return $true }  # Bypass queue if forced
    
    if (-not $Queue -or -not $Queue.ContainsKey($RemoteHost)) {
        return $true
    }
    
    $elapsed = ((Get-Date) - $Queue[$RemoteHost]).TotalSeconds
    if ($elapsed -lt $Duration) {
        $remainingMinutes = [math]::Round(($Duration - $elapsed) / 60)
        Write-Log -Message "Skipping (retry in $remainingMinutes minutes)" -RemoteHost $RemoteHost
        return $false
    }
    
    return $true
}

function Should-SkipUpdate {
    param(
        [object]$HostData,
        [int]$Days
    )
    
    if (-not $HostData.last_successful_update_timestamp) { return $false }
    
    try {
        $lastUpdate = [datetime]::Parse($HostData.last_successful_update_timestamp)
        return ((Get-Date) - $lastUpdate).TotalDays -lt $Days
    } catch {
        return $false
    }
}

# ============================================
# REMOTE UPDATE EXECUTION
# ============================================

function Invoke-RemoteUpdate {
    param(
        [string]$RemoteHost,
        [string]$PsExecPath,
        [string]$ScriptRoot = $null
    )
    
    Write-Log -Message "Starting update" -RemoteHost $RemoteHost -Level Info -ScriptRoot $ScriptRoot
    
    try {
        if (-not (Test-NetConnection -ComputerName $RemoteHost -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            throw "Cannot connect to SMB port 445 (required for PsExec)"
        }
        
        # Updated $psCommand: Uses only MS tools (Windows Update COM + winget auto-install for apps). Omits -s flag in PsExec for user context.
        $psCommand = @'
$ProgressPreference = 'SilentlyContinue'
$log = @(); $needsReboot = $false; $exitCode = 0
try {
    $log += "Starting update session at $(Get-Date -Format 'o')";
    if (-not (Get-Service -Name wuauserv -ErrorAction SilentlyContinue)) {
        throw "Windows Update service not found"
    }
    $log += "Windows Update service found.";
    $updateSession = New-Object -ComObject Microsoft.Update.Session;
    $log += "Update session created.";
    $updateSearcher = $updateSession.CreateUpdateSearcher();
    $log += "Update searcher created.";
    $log += "Searching for updates...";
    $searchResult = $updateSearcher.Search('IsInstalled=0 and IsHidden=0');
    $log += "Search completed. Found $($searchResult.Updates.Count) updates.";
    if ($searchResult.Updates.Count -eq 0) { 
        $log += 'No updates available. System is up to date.';
        $log | Out-String; 
        exit 0  # Treat as success
    }

    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl;
    foreach ($update in $searchResult.Updates) {
        if ($update.IsHidden) { continue }
        $updatesToDownload.Add($update) | Out-Null;
    }

    $downloader = $updateSession.CreateUpdateDownloader();
    $downloader.Updates = $updatesToDownload;
    $log += "Starting download of $($downloader.Updates.Count) updates...";
    $downloadResult = $downloader.Download();
    $log += "Download completed. ResultCode: $($downloadResult.ResultCode)";
    if ($downloadResult.ResultCode -notin @(2,3)) { throw "Download failed with code $($downloadResult.ResultCode)" }

    $updatesToInstall = $updatesToDownload
    $installer = $updateSession.CreateUpdateInstaller();
    $installer.Updates = $updatesToInstall;
    $log += "Starting installation of $($updatesToInstall.Count) updates...";
    $installResult = $installer.Install();
    $log += "Installation completed. ResultCode: $($installResult.ResultCode); RebootRequired: $($installResult.RebootRequired)";
    $needsReboot = $installResult.RebootRequired;
    if ($needsReboot) { $log += 'Reboot required.' }

    if ($installResult.ResultCode -in @(2,3)) {
        $exitCode = 0
        try {
            Start-Process -FilePath gpupdate -ArgumentList '/force' -NoNewWindow -Wait
            $log += "gpupdate /force completed.";
        } catch { $log += "gpupdate failed: $($_.Exception.Message)" }

        # Use winget for non-Store app updates (auto-install if missing, per [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/package-manager/winget/))
        # Note: Microsoft Store apps cannot be upgraded via winget/PowerShell ([github.com](https://github.com/microsoft/winget-cli/issues/2854))
        $wingetWorked = $false
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            $log += "Winget not found; installing via Microsoft (aka.ms/getwinget).";
            try {
                $wingetUrl = "https://aka.ms/getwinget"  # Official MS installer ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows/package-manager/winget/))
                $tempPath = Join-Path $env:TEMP "winget.msix"
                Invoke-WebRequest -Uri $wingetUrl -OutFile $tempPath -UseBasicParsing
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$tempPath`" /quiet /norestart" -Wait -NoNewWindow  # Silent install
                Remove-Item $tempPath -ErrorAction SilentlyContinue
            } catch { $log += "Winget install failed: $($_.Exception.Message)" }
        }
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                $log += "Running winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --include-unknown";
                & winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --include-unknown  # Full command with MS-developed flags ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade))
                if ($LASTEXITCODE -eq 0) {
                    $log += "Winget upgrades completed.";
                    $wingetWorked = $true
                } else {
                    $log += "Winget upgrade failed with code $LASTEXITCODE."
                }
            } catch { $log += "Winget execution failed: $($_.Exception.Message)" }
        } else {
            $log += "Winget install failed; skipping app upgrades (Microsoft Store apps require manual updates).";
        }
        if (-not $wingetWorked) { $log += "Note: Microsoft Store apps cannot be upgraded via winget/PowerShell ([github.com](https://github.com/microsoft/winget-cli/issues/2854)). Manually check Windows Store for updates." }
    } else {
        throw "Install failed with code $($installResult.ResultCode)"
    }
} catch {
    $log += "Exception: $($_.Exception.Message)";
    $exitCode = 1
} finally {
    $log += "Update session ended at $(Get-Date -Format 'o')";
    $log | Out-String
    exit $exitCode
}
'@

        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psCommand))

        # Updated PsExec args: Removed -s to run in user context (avoids "No package found" errors in admin mode ([community.spiceworks.com](https://community.spiceworks.com/t/winget-fails-to-upgrade-apps-when-run-as-system/1058983))). Uses -h for highest privileges.
        $psExecArgs = @(
            "-nobanner",
            "-accepteula",
            "-h",  # Highest privileges (no SYSTEM)
            "\\$RemoteHost",
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            $encodedCommand
        )
        
        $psi = [System.Diagnostics.ProcessStartInfo]@{
            FileName = $PsExecPath
            Arguments = "`"$($psExecArgs -join '" "')`""
            RedirectStandardOutput = $true
            RedirectStandardError = $true
            UseShellExecute = $false
            CreateNoWindow = $true
        }
        
        $process = [System.Diagnostics.Process]::Start($psi)
        $timeout = 600000  # 10 minutes
        
        if (-not $process.WaitForExit($timeout)) {
            $process.Kill()
            throw "Update timed out after 10 minutes"
        }
        
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        if ($stdout) {
            $stdout -split "`n" | ForEach-Object { if ($_) { Write-Log -Level Info -RemoteHost $RemoteHost -Message $_ } }
        }
        if ($stderr) {
            Write-Log -Level Error -RemoteHost $RemoteHost -Message $stderr -ScriptRoot $ScriptRoot
        }
        
        return @{
            ExitCode = $process.ExitCode
            StdOut = $stdout
            StdErr = $stderr
        }
        
    } catch {
        Write-Log -Level Error -RemoteHost $RemoteHost -Message $_ -ScriptRoot $ScriptRoot
        return @{
            ExitCode = 1
            StdOut = ""
            StdErr = $_.Exception.Message
        }
    }
}

# ============================================
# PARALLEL HOST PROCESSING (updated inline)
# ============================================

function Process-SingleHost { ... }  # Unchanged

# ============================================
# INITIALIZATION (unchanged)
# ============================================

function Initialize-Environment {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "This script requires PowerShell 7 or higher. Current version: $($PSVersionTable.PSVersion)"
    }
    
    $script:PsExecPath = Get-ChildItem -Path $PSScriptRoot -Filter "PsExec*.exe" | 
        Select-Object -First 1 -ExpandProperty FullName
    
    if (-not $PsExecPath) {
        throw "PsExec.exe not found in script directory"
    }
    
    $logsDir = Join-Path $PSScriptRoot ".logs"
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force -ErrorAction Stop | Out-Null
    }
    
    Write-Log -Message "Environment initialized"
    foreach ($system in $yamlData.systems) {
        Write-Log -Level Info -Message "Found $($system.hostname) : Last update timestamp $($system.last_successful_update_timestamp)"
    }
}

# ============================================
# MAIN EXECUTION
# ============================================

Write-Host "`nWindows Update Automation Script (Optimized Parallel Edition with Winget Repair)" -ForegroundColor Cyan
Write-Host ("=" * 40) -ForegroundColor Cyan

try {
    Initialize-Environment
    
    $yamlData = Load-YamlData -File $YamlFile
    $hostQueue = Get-HostQueue -File $QueueFile
    
    # Auto-set Force for single hostname if not specified
    $effectiveForce = if ($HostName -and -not $PSBoundParameters.ContainsKey('Force')) { $true } else { $Force }
    
    # Determine target hosts: If $HostName provided, use it; otherwise, use the file
    if ($HostName) {
        $targetHosts = @($HostName)
    } else {
        $targetHosts = Get-TargetHosts -File $HostsFile
    }
    
    if (-not $targetHosts) {
        Write-Log -Level Error -Message "No valid hosts found"
        exit 1
    }
    
    Write-Log -Message "Pre-filtering hosts for connectivity and recent updates" -Level Info

    # Sequential filtering (simpler and more reliable than parallel)
    $filteredHosts = @()
    foreach ($hostname in $targetHosts) {
        # Skip connectivity if Force is on (to allow offline debugging)
        if (-not $effectiveForce -and -not (Test-Connection -ComputerName $hostname -Count 1 -Quiet -WarningAction SilentlyContinue)) { 
            continue 
        }
    
        $hostData = $yamlData.systems | Where-Object { $_.hostname -eq $hostname }
        if (-not $effectiveForce -and (Should-SkipUpdate -HostData $hostData -Days $SkipDays)) { 
            continue 
        }

        $filteredHosts += $hostname
    }
    
    $targetHosts = $filteredHosts
    
    Write-Log -Message "Processing $($targetHosts.Count) hosts with throttle limit of $ThrottleLimit $(if ($effectiveForce) { '(forced mode)' } else { '' })" -Level Info

    # Parallel host processing using ForEach-Object -Parallel
    $results = $targetHosts | ForEach-Object -Parallel {
        # Accessing using variables
        $computerName = $_
        $PsExecPath = $using:script:PsExecPath
        $SkipDays = $using:SkipDays
        $QueueDuration = $using:QueueDuration
        $hostQueue = $using:hostQueue
        $yamlData = $using:yamlData
        $scriptRoot = $using:script:PSScriptRoot
        $effectiveForce = $using:effectiveForce

        # Inline logging function
        function Write-LogInline {
            param(
                [string]$Message,
                [string]$RemoteHost = "",
                [ValidateSet('Info', 'Warning', 'Error', 'Success')]$Level = 'Info'
            )
            $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $logMessage = "[$timestamp] [$Level]"
            if ($RemoteHost) { $logMessage += " [$RemoteHost]" }
            $logMessage += " $Message"
            Write-Host $logMessage -ForegroundColor @{
                'Error' = 'Red'; 'Warning' = 'Yellow'; 'Success' = 'Green'; 'Info' = 'White'
            }[$Level]
            $logFile = Join-Path $scriptRoot ".logs\update_script.log"
            try {
                $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
            } catch {}
        }

        # Inline queue check logic
        function Should-ProcessHostInline {
            param([string]$RemoteHost, [hashtable]$Queue, [int]$Duration, [bool]$Force)
            if ($Force) { return $true }
            if (-not $Queue -or -not $Queue.ContainsKey($RemoteHost)) { return $true }
            $elapsed = ((Get-Date) - $Queue[$RemoteHost]).TotalSeconds
            return $elapsed -ge $Duration
        }

        # Inline skip check logic
        function Should-SkipUpdateInline {
            param([object]$HostData, [int]$Days)
            if (-not $HostData.last_successful_update_timestamp) { return $false }
            try {
                $lastUpdate = [datetime]::Parse($HostData.last_successful_update_timestamp)
                return ((Get-Date) - $lastUpdate).TotalDays -lt $Days
            } catch { return $false }
        }

        # Check queue inline
        if (-not (Should-ProcessHostInline -RemoteHost $computerName -Queue $hostQueue -Duration $QueueDuration -Force $effectiveForce)) {
            $statusMessage = if ($effectiveForce) { 'Skipped-Queue (force bypassed)' } else { 'Skipped-Queue' }
            return @{
                Hostname = $computerName
                Status = $statusMessage
                UpdateSuccess = $false
                NeedsQueue = $false
            }
        }

        # Check skip based on yaml (skip if Force not enabled)
        if (-not $effectiveForce) {
            $hostData = $yamlData.systems | Where-Object { $_.hostname -eq $computerName }
            if (Should-SkipUpdateInline -HostData $hostData -Days $SkipDays) {
                return @{
                    Hostname = $computerName
                    Status = 'Skipped-RecentUpdate'
                    UpdateSuccess = $false
                    NeedsQueue = $false
                }
            }
        }

        Write-LogInline -Message "Starting update" -RemoteHost $computerName -Level Info

        try {
            if (-not (Test-NetConnection -ComputerName $computerName -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
                throw "Cannot connect to SMB port 445 (required for PsExec)"
            }

            $psCommand = @'
$ProgressPreference = 'SilentlyContinue'
$log = @(); $needsReboot = $false; $exitCode = 0
try {
    $log += "Starting update session at $(Get-Date -Format 'o')";
    if (-not (Get-Service -Name wuauserv -ErrorAction SilentlyContinue)) {
        throw "Windows Update service not found"
    }
    $log += "Windows Update service found.";
    $updateSession = New-Object -ComObject Microsoft.Update.Session;
    $log += "Update session created.";
    $updateSearcher = $updateSession.CreateUpdateSearcher();
    $log += "Update searcher created.";
    $log += "Searching for updates...";
    $searchResult = $updateSearcher.Search('IsInstalled=0 and IsHidden=0');
    $log += "Search completed. Found $($searchResult.Updates.Count) updates.";
    if ($searchResult.Updates.Count -eq 0) { 
        $log += 'No updates available. System is up to date.';
        $log | Out-String; 
        exit 0  # Treat as success
    }

    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl;
    foreach ($update in $searchResult.Updates) {
        if ($update.IsHidden) { continue }
        $updatesToDownload.Add($update) | Out-Null;
    }

    $downloader = $updateSession.CreateUpdateDownloader();
    $downloader.Updates = $updatesToDownload;
    $log += "Starting download of $($downloader.Updates.Count) updates...";
    $downloadResult = $downloader.Download();
    $log += "Download completed. ResultCode: $($downloadResult.ResultCode)";
    if ($downloadResult.ResultCode -notin @(2,3)) { throw "Download failed with code $($downloadResult.ResultCode)" }

    # Reuse downloaded collection for install
    $updatesToInstall = $updatesToDownload
    $installer = $updateSession.CreateUpdateInstaller();
    $installer.Updates = $updatesToInstall;
    $log += "Starting installation of $($updatesToInstall.Count) updates...";
    $installResult = $installer.Install();
    $log += "Installation completed. ResultCode: $($installResult.ResultCode); RebootRequired: $($installResult.RebootRequired)";
    $needsReboot = $installResult.RebootRequired;
    if ($needsReboot) { $log += 'Reboot required.' }

    if ($installResult.ResultCode -in @(2,3)) {
        $exitCode = 0
        try {
            Start-Process -FilePath gpupdate -ArgumentList '/force' -NoNewWindow -Wait
            $log += "gpupdate /force completed.";
        } catch { $log += "gpupdate failed: $($_.Exception.Message)" }

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $wingetWorked = $false
            try {
                $log += "Running winget upgrade --all...";
                $wingetOutput = & winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --include-unknown 2>&1
                $log += "winget upgrade completed.";
                $wingetWorked = $true
            } catch { 
                $log += "winget execution failed: $($_.Exception.Message)"
                # Attempt repair if 'winget' is not recognized or fails
                if ($_.Exception.Message -match 'winget.*not recognized' -or $LASTEXITCODE -ne 0) {
                    $log += "Attempting to repair Winget installation";
                    try {
                        # Reinstall Winget
                        $wingetUrl = "https://github.com/microsoft/winget-cli/releases/download/v1.7.10882-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
                        $tempPath = Join-Path $env:TEMP "WingetInstaller.msixbundle"
                        Invoke-WebRequest -Uri $wingetUrl -OutFile $tempPath -UseBasicParsing
                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c \`"$tempPath\`" /quiet /norestart" -Wait -NoNewWindow
                        Remove-Item $tempPath -ErrorAction SilentlyContinue
                        $env:Path += ";$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_1.21.24171.0_neutral__8wekyb3d8bbwe\"
                        if (Get-Command winget -ErrorAction SilentlyContinue) {
                            $log += "Winget repaired; retrying upgrade.";
                            try {
                                $wingetOutput = & winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --include-unknown 2>&1
                                $log += "winget upgrade completed after repair.";
                                $wingetWorked = $true
                            } catch { $log += "Winget upgrade failed even after repair: $($_.Exception.Message)" }
                        } else {
                            $log += "Winget repair failed; skipping winget upgrades.";
                        }
                    } catch { $log += "Winget repair error: $($_.Exception.Message)" }
                }
            }
            if (-not $wingetWorked) { $log += "winget upgrades were not successful." }
        } else {
            $log += "winget not found; skipping winget upgrades.";
        }
    } else {
        throw "Install failed with code $($installResult.ResultCode)"
    }
} catch {
    $log += "Exception: $($_.Exception.Message)";
    $exitCode = 1
} finally {
    $log += "Update session ended at $(Get-Date -Format 'o')";
    $log | Out-String
    exit $exitCode
}
'@

            $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psCommand))

            $psExecArgs = @(
                "-nobanner",
                "-accepteula",
                "-s",
                "-h",
                "\\$computerName",
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                $encodedCommand
            )

            $psi = [System.Diagnostics.ProcessStartInfo]@{
                FileName = $PsExecPath
                Arguments = "`"$($psExecArgs -join '" "')`""
                RedirectStandardOutput = $true
                RedirectStandardError = $true
                UseShellExecute = $false
                CreateNoWindow = $true
            }

            $process = [System.Diagnostics.Process]::Start($psi)
            $timeout = 600000  # 10 minutes

            if (-not $process.WaitForExit($timeout)) {
                $process.Kill()
                throw "Update timed out after 10 minutes"
            }

            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()

            if ($stdout) {
                $stdout -split "`n" | Where-Object { $_ } | ForEach-Object { Write-LogInline -Level Info -RemoteHost $computerName -Message $_ }
            }
            if ($stderr) {
                Write-LogInline -Level Error -RemoteHost $computerName -Message $stderr
            }

            $exitCode = $process.ExitCode

        } catch {
            Write-LogInline -Level Error -RemoteHost $computerName -Message $_
            $exitCode = 1
        }

        if ($exitCode -eq 0) {
            Write-LogInline -Level Success -RemoteHost $computerName -Message "Update completed successfully"
            return @{
                Hostname = $computerName
                Status = 'Success'
                UpdateSuccess = $true
                NeedsQueue = $false
            }
        } else {
            Write-LogInline -Level Error -RemoteHost $computerName -Message "Update failed"
            return @{
                Hostname = $computerName
                Status = 'Failed'
                UpdateSuccess = $false
                NeedsQueue = $true
            }
        }
    } -ThrottleLimit $ThrottleLimit
    
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    
    foreach ($result in $results) {
        $hostEntry = $yamlData.systems | Where-Object { $_.hostname -eq $result.Hostname }
        
        if (-not $hostEntry) {
            $hostEntry = @{
                hostname = $result.Hostname
                last_connection_timestamp = $timestamp
                last_successful_update_timestamp = $null
                update_success = $false
            }
            $yamlData.systems += $hostEntry
        }
        
        switch ($result.Status) {
            'Success' {
                $hostEntry.last_connection_timestamp = $timestamp
                $hostEntry.last_successful_update_timestamp = $timestamp
                $hostEntry.update_success = $true
                if ($hostQueue.ContainsKey($result.Hostname)) { $hostQueue.Remove($result.Hostname) }  # Clear from queue on success
            }
            'Failed' {
                $hostEntry.last_connection_timestamp = $timestamp
                $hostEntry.update_success = $false
                if ($result.NeedsQueue) {
                    $hostQueue[$result.Hostname] = Get-Date
                }
            }
            'Error' {
                $hostEntry.update_success = $false
                if ($result.NeedsQueue) {
                    $hostQueue[$result.Hostname] = Get-Date
                }
            }
            { $_ -like 'Skipped-*' } {
                # No changes for skipped (except possibly logging)
            }
        }
    }
    
    Save-YamlData -Data $yamlData -File $YamlFile
    Save-HostQueue -Queue $hostQueue -File $QueueFile
    
    $stats = @{
        Success = ($results | Where-Object { $_.Status -eq 'Success' }).Count
        Skipped = ($results | Where-Object { $_.Status -like 'Skipped-*' }).Count
        Failed = ($results | Where-Object { $_.Status -eq 'Failed' -or $_.Status -eq 'Error' }).Count
        Queued = $hostQueue.Count
    }
    
    Write-Host "`n$('=' * 40)" -ForegroundColor Cyan
    Write-Host "EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host "$('=' * 40)" -ForegroundColor Cyan
    Write-Host "Total Hosts:    $($targetHosts.Count)"
    Write-Host "Successful:     $($stats.Success)" -ForegroundColor Green
    Write-Host "Skipped:        $($stats.Skipped)" -ForegroundColor Yellow
    Write-Host "Failed/Errors:  $($stats.Failed)" -ForegroundColor Red
    Write-Host "Queued:         $($stats.Queued)" -ForegroundColor Yellow
    
    if ($hostQueue.Count -gt 0) {
        Write-Host "`nHosts in retry queue:" -ForegroundColor Yellow
        $hostQueue.GetEnumerator() | ForEach-Object {
            $wait = [math]::Round(($QueueDuration - ((Get-Date) - $_.Value).TotalSeconds) / 60)
            if ($wait -gt 0) {
                Write-Host "  $($_.Key) - retry in $wait minutes"
            }
        }
    }
    
} catch {
    Write-Log -Level Error -Message "Script error: $_"
    exit 1
} finally {
    if ($script:LogLock) {
        $script:LogLock.Dispose()
    }
    Write-Host "`nScript completed" -ForegroundColor Green
}