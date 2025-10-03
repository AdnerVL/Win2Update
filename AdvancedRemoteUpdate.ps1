[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$HostsFile = (Join-Path $PSScriptRoot 'hosts.txt'),
    
    [Parameter(Position=1)]
    [string]$YamlFile = (Join-Path $PSScriptRoot 'hosts_tracking.yaml'),
    
    [Parameter(Position=2)]
    [string]$QueueFile = (Join-Path $PSScriptRoot 'hostQueue.txt'),
    
    [Parameter(Position=3)]
    [ValidateRange(0, 365)]
    [int]$SkipDays = 5,
    
    [switch]$AutoReboot,
    
    [ValidateRange(0, 86400)]
    [int]$QueueDuration = 10800
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

# ============================================
# CORE FUNCTIONS
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [string]$RemoteHost = "",
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
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
    
    Write-Host $logMessage -ForegroundColor $colors[$Level]
    
    $logFile = Join-Path $PSScriptRoot ".logs\update_script.log"
    $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# ============================================
# YAML HANDLING
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
  last_connection_timestamp: $($system.last_connection_timestamp ?? '')
  last_successful_update_timestamp: $($system.last_successful_update_timestamp ?? '')
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
    
    $content = Get-Content -Path $File -Raw -ErrorAction SilentlyContinue
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
# QUEUE MANAGEMENT
# ============================================

function Get-HostQueue {
    param([string]$File)
    
    $queue = @{}
    if (-not (Test-Path $File)) { return $queue }
    
    try {
        Get-Content $File -ErrorAction Stop | ForEach-Object {
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
    
    # Clean expired entries safely
    $now = Get-Date
    $keysToRemove = $queue.Keys | Where-Object { 
        ($now - $queue[$_]).TotalSeconds -gt $QueueDuration 
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
        $lines | Out-File -FilePath $File -Force -Encoding utf8
    } else {
        Clear-Content -Path $File -ErrorAction SilentlyContinue
    }
}

# ============================================
# HOST MANAGEMENT
# ============================================

function Get-TargetHosts {
    param([string]$File)
    
    if (-not (Test-Path $File)) {
        Write-Log -Level Warning -Message "Hosts file not found: $File"
        return @()
    }
    
    $hosts = Get-Content $File -ErrorAction SilentlyContinue | 
        Where-Object { $_ -and $_ -match '^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$' } |
        ForEach-Object { $_.Trim() }
    
    Write-Log -Message "Found $($hosts.Count) valid hosts"
    return $hosts
}

function Should-ProcessHost {
    param(
        [string]$RemoteHost,
        [hashtable]$Queue
    )
    
    if (-not $Queue -or -not $Queue.ContainsKey($RemoteHost)) {
        return $true
    }
    
    $elapsed = ((Get-Date) - $Queue[$RemoteHost]).TotalSeconds
    if ($elapsed -lt $QueueDuration) {
        $remainingMinutes = [math]::Round(($QueueDuration - $elapsed) / 60)
        Write-Log -Message "Skipping $RemoteHost (retry in $remainingMinutes minutes)"
        return $false
    }
    
    $Queue.Remove($RemoteHost)
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

function Update-HostData {
    param(
        [hashtable]$YamlData,
        [string]$Hostname,
        [bool]$UpdateSuccess,
        [string]$UpdateTimestamp = $null,
        [string]$ConnectionTimestamp = $null
    )
    
    $hostEntry = $YamlData.systems | Where-Object { $_.hostname -eq $Hostname }
    
    if (-not $hostEntry) {
        $hostEntry = @{
            hostname = $Hostname
            last_connection_timestamp = $ConnectionTimestamp
            last_successful_update_timestamp = $UpdateTimestamp
            update_success = $UpdateSuccess
        }
        $YamlData.systems += $hostEntry
    } else {
        if ($ConnectionTimestamp) { $hostEntry.last_connection_timestamp = $ConnectionTimestamp }
        if ($UpdateTimestamp) { $hostEntry.last_successful_update_timestamp = $UpdateTimestamp }
        $hostEntry.update_success = $UpdateSuccess
    }
}

# ============================================
# REMOTE UPDATE EXECUTION
# ============================================

function Invoke-RemoteUpdate {
    param(
        [string]$RemoteHost,
        [string]$PsExecPath
    )
    
    Write-Log -Message "Starting update" -RemoteHost $RemoteHost -Level Info
    
    try {
        # Verify SMB connectivity (port 445) for PsExec
        if (-not (Test-NetConnection -ComputerName $RemoteHost -Port 445 -InformationLevel Quiet)) {
            throw "Cannot connect to SMB port 445 (required for PsExec)"
        }
        
        # PowerShell command to execute updates
        $psCommand = @'
$log = @(); $needsReboot = $false;
try {
    $log += "Starting update session at $(Get-Date -Format 'o')";
    if (-not (Get-Service -Name wuauserv -ErrorAction SilentlyContinue)) {
        $log += "Windows Update service not found"; exit 1
    }
    $log += "Windows Update service found.";
    $updateSession = New-Object -ComObject Microsoft.Update.Session;
    $log += "Update session created.";
    $updateSearcher = $updateSession.CreateUpdateSearcher();
    $log += "Update searcher created.";
    $log += "Searching for updates...";
    $searchResult = $updateSearcher.Search('IsInstalled=0');
    $log += "Search completed. Found $($searchResult.Updates.Count) updates.";
    if ($searchResult.Updates.Count -eq 0) { $log += 'No updates available.'; $log | Out-String; exit 0 }
    $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl;
    foreach ($update in $searchResult.Updates) {
        $log += "Processing update: $($update.Title) (KB$($update.KBArticleIDs -join ','))";
        if ($update.IsDownloaded -or $update.AutoSelectOnWebSites) {
            $updatesToInstall.Add($update) | Out-Null;
            $log += "Selected for install: $($update.Title)";
        } else {
            $log += "Skipped (not downloaded or auto-select): $($update.Title)";
        }
    }
    if ($updatesToInstall.Count -eq 0) { $log += 'No installable updates.'; $log | Out-String; exit 0 }
    $downloader = $updateSession.CreateUpdateDownloader();
    $downloader.Updates = $updatesToInstall;
    $log += "Starting download of $($updatesToInstall.Count) updates...";
    $downloadResult = $downloader.Download();
    $log += "Download completed. Result code: $($downloadResult.ResultCode) HResult: $($downloadResult.HResult)";
    if ($downloadResult.ResultCode -ne 2) { throw "Download failed with code $($downloadResult.ResultCode)" }
    $installer = $updateSession.CreateUpdateInstaller();
    $installer.Updates = $updatesToInstall;
    $log += "Starting installation...";
    $installResult = $installer.Install();
    $log += "Installation completed. Result code: $($installResult.ResultCode) HResult: $($installResult.HResult)";
    $needsReboot = $installResult.RebootRequired;
    if ($needsReboot) { $log += 'Reboot required.' }
    $log | Out-String;
    if ($installResult.ResultCode -eq 2) { exit 0 } else { exit 1 }
} catch {
    $log += "Exception: $($_.Exception.GetType().FullName) - $($_.Exception.Message)";
    $log += "StackTrace: $($_.Exception.StackTrace)";
    $log | Out-String; exit 1
} finally {
    $log += "Update session ended at $(Get-Date -Format 'o')";
    $log | Out-String
}
'@

        # Base64-encode the command to avoid escaping issues
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psCommand))

        # PsExec arguments
        $args = @(
            "-nobanner",
            "-accepteula",
            "-s",
            "-h",
            "\\$RemoteHost",
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy Bypass",
            "-EncodedCommand",
            $encodedCommand
        )
        
        $psi = [System.Diagnostics.ProcessStartInfo]@{
            FileName = $PsExecPath
            Arguments = $args -join ' '
            RedirectStandardOutput = $true
            RedirectStandardError = $true
            UseShellExecute = $false
            CreateNoWindow = $true
        }
        
        $process = [System.Diagnostics.Process]::Start($psi)
        $timeout = 900000 # 15 minutes in milliseconds
        
        if (-not $process.WaitForExit($timeout)) {
            $process.Kill()
            throw "Update timed out after 15 minutes"
        }
        
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        # Log output
        if ($stdout) {
            $stdout -split "`n" | ForEach-Object { if ($_) { Write-Log -Level Info -RemoteHost $RemoteHost -Message $_ } }
        }
        if ($stderr) {
            Write-Log -Level Error -RemoteHost $RemoteHost -Message $stderr
        }
        
        return @{
            ExitCode = $process.ExitCode
            StdOut = $stdout
            StdErr = $stderr
        }
        
    } catch {
        Write-Log -Level Error -RemoteHost $RemoteHost -Message $_
        return @{
            ExitCode = 1
            StdOut = ""
            StdErr = $_.Exception.Message
        }
    }
}

# ============================================
# INITIALIZATION
# ============================================

function Initialize-Environment {
    # Find PsExec
    $script:PsExecPath = Get-ChildItem -Path $PSScriptRoot -Filter "PsExec*.exe" | 
        Select-Object -First 1 -ExpandProperty FullName
    
    if (-not $PsExecPath) {
        throw "PsExec.exe not found in script directory"
    }
    
    # Create required directories
    $logsDir = Join-Path $PSScriptRoot ".logs"
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }
    
    Write-Log -Message "Environment initialized" -Level Info
}

# ============================================
# MAIN EXECUTION
# ============================================

Write-Host "`nWindows Update Automation Script" -ForegroundColor Cyan
Write-Host ("=" * 40) -ForegroundColor Cyan

try {
    # Initialize
    Initialize-Environment
    
    # Load data
    $yamlData = Load-YamlData -File $YamlFile
    $hostQueue = Get-HostQueue -File $QueueFile
    $targetHosts = Get-TargetHosts -File $HostsFile
    
    if (-not $targetHosts) {
        Write-Log -Level Error -Message "No valid hosts found"
        exit 1
    }
    
    # Statistics
    $stats = @{
        Success = 0
        Skipped = 0
        Failed = 0
        Unreachable = 0
    }
    
    Write-Log -Message "Processing $($targetHosts.Count) hosts" -Level Info
    
    # Process each host
    foreach ($computerName in $targetHosts) {
        Write-Host "`n$('=' * 40)" -ForegroundColor Gray
        Write-Log -Message "Processing host" -RemoteHost $computerName -Level Info
        
        # Check queue
        if (-not (Should-ProcessHost -RemoteHost $computerName -Queue $hostQueue)) {
            $stats.Skipped++
            continue
        }
        
        # Test connectivity
        if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet)) {
            Write-Log -Level Warning -RemoteHost $computerName -Message "Host unreachable"
            $hostQueue[$computerName] = Get-Date
            $stats.Unreachable++
            Update-HostData -YamlData $yamlData -Hostname $computerName -UpdateSuccess $false
            continue
        }
        
        # Update connection timestamp
        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Update-HostData -YamlData $yamlData -Hostname $computerName -UpdateSuccess $false -ConnectionTimestamp $timestamp
        
        # Check if recently updated
        $hostData = $yamlData.systems | Where-Object { $_.hostname -eq $computerName }
        if (Should-SkipUpdate -HostData $hostData -Days $SkipDays) {
            Write-Log -Level Info -RemoteHost $computerName -Message "Recently updated, skipping"
            $stats.Skipped++
            continue
        }
        
        # Perform update
        $result = Invoke-RemoteUpdate -RemoteHost $computerName -PsExecPath $PsExecPath
        
        if ($result.ExitCode -eq 0) {
            Write-Log -Level Success -RemoteHost $computerName -Message "Update completed successfully"
            $updateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            Update-HostData -YamlData $yamlData -Hostname $computerName -UpdateSuccess $true -UpdateTimestamp $updateTime
            $stats.Success++
        } else {
            Write-Log -Level Error -RemoteHost $computerName -Message "Update failed"
            Update-HostData -YamlData $yamlData -Hostname $computerName -UpdateSuccess $false
            $hostQueue[$computerName] = Get-Date
            $stats.Failed++
        }
        
        # Save progress
        Save-YamlData -Data $yamlData -File $YamlFile
    }
    
    # Save final state
    Save-HostQueue -Queue $hostQueue -File $QueueFile
    
    # Display summary
    Write-Host "`n$('=' * 40)" -ForegroundColor Cyan
    Write-Host "EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host "$('=' * 40)" -ForegroundColor Cyan
    Write-Host "Total Hosts:    $($targetHosts.Count)"
    Write-Host "Successful:     $($stats.Success)" -ForegroundColor Green
    Write-Host "Skipped:        $($stats.Skipped)" -ForegroundColor Yellow
    Write-Host "Failed:         $($stats.Failed)" -ForegroundColor Red
    Write-Host "Unreachable:    $($stats.Unreachable)" -ForegroundColor Red
    Write-Host "Queued:         $($hostQueue.Count)" -ForegroundColor Yellow
    
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
    Write-Host "`nScript completed" -ForegroundColor Green
}