<#
    .SYNOPSIS
        Advanced Remote Windows Update Script with YAML Tracking

    .DESCRIPTION
        Automates Windows Update, winget upgrades, and firmware (via MSUpdate) across remote hosts using PsExec. Tracks status in a YAML database to skip hosts updated within 5 days.

        * YAML-based tracking (hosts_tracking.yaml) for hostname, last_connection_timestamp, last_successful_update_timestamp, update_success.
        * Skips hosts if last successful update < 5 days ago.
        * Online checks via Test-Connection; updates connection timestamp.
        * Silent remote execution: Windows Updates, winget, firmware.*
        * Retry queuing for failures/unreachable (default 3 hours).
        * Optional auto-reboot.
        * Structured JSON logging.
        * Admin elevation required.

    .PARAMETER HostsFile
        Path to the file containing a list of target hosts (one per line). Defaults to "hosts.txt" in the script directory.

    .PARAMETER YamlFile
        Path to the YAML tracking database file. Defaults to "hosts_tracking.yaml" in the script directory.

    .PARAMETER QueueFile
        Path to the retry queue file. Defaults to "hostQueue.txt" in the script directory.

    .PARAMETER ErrorLogFile
        Path to the error log file. Successes are logged to a separate file with ".success.log" suffix.

    .PARAMETER QueueDuration
        Time in seconds before a host is retried after a failure. Defaults to 10,800 seconds (3 hours).

    .PARAMETER PsExecPath
        Path to PsExec.exe. Defaults to "PsExec.exe" in the script directory.

    .PARAMETER DefaultReboot
        When specified, remote hosts default to rebooting if updates require it (unless overridden by YAML per-host setting). Defaults to false (user manual reboot).

    .PARAMETER SkipDays
        Days to skip updates if last successful update was within this period. Defaults to 5.

    .EXAMPLE
        .\AdvancedRemoteUpdate.ps1 -HostsFile "hosts.txt" -AutoReboot -SkipDays 7

        Processes hosts from hosts.txt, reboots if needed, skips if updated within 7 days.
#>

param(
    [string]$HostsFile,
    [string]$YamlFile,
    [string]$QueueFile,
    [string]$ErrorLogFile,
    [ValidateRange(1, [int]::MaxValue)]
    [int]$QueueDuration = 3 * 60 * 60,
    [string]$PsExecPath,
    [switch]$AutoReboot = $false,
    [ValidateRange(0, 365)]
    [int]$SkipDays = 5,
    [switch]$ForceRetry = $false,
    [switch]$SkipQueue = $false,
    [switch]$Debug = $false
)

# Set error handling preferences
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Initialize error codes
$script:ERROR_CODES = @{
    SUCCESS = 0
    GENERAL_ERROR = 1
    ADMIN_REQUIRED = 2
    FILE_NOT_FOUND = 3
    CONNECTION_ERROR = 4
    UPDATE_FAILURE = 5
    INVALID_CONFIG = 6
}

Write-Host "Script started."

# Function to handle YAML data without requiring the PowerShell-Yaml module
function ConvertFrom-Yaml {
    param([string]$YamlContent)
    
    $data = @{
        systems = @()
    }
    
    # Simple YAML parsing for our specific needs
    try {
        $lines = $YamlContent -split "`n" | ForEach-Object { $_.Trim() }
        $currentSystem = $null
        
        foreach ($line in $lines) {
            if ($line -match '^-\s*hostname:\s*(.+)$') {
                if ($currentSystem) {
                    $data.systems += $currentSystem
                }
                $currentSystem = @{
                    hostname = $matches[1]
                    last_connection_timestamp = $null
                    last_successful_update_timestamp = $null
                    update_success = $false
                }
            }
            elseif ($line -match '^(\s+)?(last_connection_timestamp):\s*(.+)$' -and $currentSystem) {
                $currentSystem.last_connection_timestamp = $matches[3]
            }
            elseif ($line -match '^(\s+)?(last_successful_update_timestamp):\s*(.+)$' -and $currentSystem) {
                $currentSystem.last_successful_update_timestamp = $matches[3]
            }
            elseif ($line -match '^(\s+)?(update_success):\s*(true|false)$' -and $currentSystem) {
                $currentSystem.update_success = $matches[3] -eq 'true'
            }
        }
        
        if ($currentSystem) {
            $data.systems += $currentSystem
        }
    }
    catch {
        Write-Error "Error parsing YAML data: $_"
        throw
    }
    
    return $data
}

function ConvertTo-Yaml {
    param($Data)
    
    $yaml = "systems:`n"
    foreach ($system in $Data.systems) {
        $yaml += "- hostname: $($system.hostname)`n"
        $yaml += "  last_connection_timestamp: $($system.last_connection_timestamp)`n"
        $yaml += "  last_successful_update_timestamp: $($system.last_successful_update_timestamp)`n"
        $yaml += "  update_success: $($system.update_success.ToString().ToLower())`n"
    }
    
    return $yaml
}

# Enable debug output if requested
if ($Debug) {
    $DebugPreference = 'Continue'
    Write-Host "=== Script Parameters ==="
    Write-Host "HostsFile: $HostsFile"
    Write-Host "YamlFile: $YamlFile"
    Write-Host "QueueFile: $QueueFile"
    Write-Host "ErrorLogFile: $ErrorLogFile"
    Write-Host "QueueDuration: $QueueDuration"
    Write-Host "PsExecPath: $PsExecPath"
    Write-Host "AutoReboot: $AutoReboot"
    Write-Host "SkipDays: $SkipDays"
    Write-Host "ForceRetry: $ForceRetry"
    Write-Host "SkipQueue: $SkipQueue"
    Write-Host "======================="
}

# Set default file paths and ensure they exist
$logsDir = Join-Path -Path $PSScriptRoot -ChildPath '.logs'
if (-not (Test-Path -Path $logsDir)) { 
    Write-Host "Creating logs directory: $logsDir"
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null 
}

if (-not $HostsFile) { $HostsFile = Join-Path -Path $PSScriptRoot -ChildPath 'hosts.txt' }
if (-not (Test-Path $HostsFile)) {
    Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Hosts file not found: $HostsFile"
    exit $ERROR_CODES.FILE_NOT_FOUND
}

if (-not $YamlFile) { $YamlFile = Join-Path -Path $PSScriptRoot -ChildPath 'hosts_tracking.yaml' }
if (-not $QueueFile) { $QueueFile = Join-Path -Path $PSScriptRoot -ChildPath 'hostQueue.txt' }
if (-not $ErrorLogFile) { $ErrorLogFile = Join-Path -Path $logsDir -ChildPath 'error.log' }

# No need to initialize PowerShell-Yaml module anymore as we have our own YAML functions

if (-not $PsExecPath) { 
    $PsExecPath = Join-Path -Path $PSScriptRoot -ChildPath 'PsExec.exe'
    if (-not (Test-Path $PsExecPath)) {
        $PsExec64Path = Join-Path -Path $PSScriptRoot -ChildPath 'PsExec64.exe'
        if (Test-Path $PsExec64Path) {
            $PsExecPath = $PsExec64Path
        } else {
            Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Neither PsExec.exe nor PsExec64.exe found in script directory."
            exit $ERROR_CODES.UPDATE_FAILURE
        }
    }
}

# Check admin rights and elevate if needed
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script requires administrative privileges. Attempting to elevate..."
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value) { $arguments += " -$key" }
        } else {
            $arguments += " -$key `"$value`""
        }
    }
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait
        exit
    } catch {
        Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed to elevate privileges: $_"
        exit 1
    }
}


# YAML handling is now done with built-in functions

# Helper functions
function Load-YamlData {
    param([string]$File)
    if (-not (Test-Path -Path $File)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] YAML file not found. Creating empty $File."
        $initialData = @{ systems = @() }
        Save-YamlData -Data $initialData -File $File
        return $initialData
    }
    try {
        $content = Get-Content -Path $File -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            return @{ systems = @() }
        }
        ConvertFrom-Yaml -YamlContent $content
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error loading YAML from ${File}: $errorMessage"
        $fallback = @{ hosts = @() }
        Save-YamlData -Data $fallback -File $File
        return $fallback
    }
}

function Save-YamlData {
    param(
        [hashtable]$Data,
        [string]$File
    )
    try {
        $yaml = ConvertTo-Yaml -Data $Data
        $yaml | Set-Content -Path $File -Encoding UTF8 -Force
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Saved YAML data to $File."
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed to save YAML to ${File}: $errorMessage"
    }
}

function Get-StandardTimestamp {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Write-StructuredLog {
    param(
        [string]$RemoteHost,
        [string]$Status,
        [string]$Message,
        [string]$LogFile
    )
    
    # Validate parameters
    if ([string]::IsNullOrEmpty($LogFile)) {
        Write-Warning "No log file specified for structured logging"
        return
    }

    try {
        $entry = [PSCustomObject]@{
            Timestamp  = Get-StandardTimestamp
            RemoteHost = $RemoteHost
            Status     = $Status
            Message    = ($Message -replace "`r`n", " ").Trim() # Sanitize message
        }
        
        # Ensure log file directory exists
        $logDir = Split-Path -Parent $LogFile
        if (-not (Test-Path -Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        # Initialize or read existing logs
        if (Test-Path $LogFile) {
            try {
                $content = Get-Content -Raw $LogFile
                if ([string]::IsNullOrWhiteSpace($content)) {
                    $logs = @()
                } else {
                    $logs = @(ConvertFrom-Json $content -ErrorAction Stop)
                }
            } catch {
                Write-Warning "Error reading log file, reinitializing: $_"
                $logs = @()
            }
        } else {
            $logs = @()
        }
        
        # Add new entry
        $logs += $entry
        
        # Write back to file with error handling
        try {
            $logs | ConvertTo-Json -Depth 10 | Set-Content -Path $LogFile -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file $LogFile : $_"
            # Try to write to a backup location
            $backupFile = Join-Path -Path $PSScriptRoot -ChildPath ".logs\backup_$(Get-Date -Format 'yyyyMMddHHmmss').log"
            $logs | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Force
        }
    } catch {
        Write-Warning "Error in structured logging: $_"
    }
}

function Load-HostQueue {
    param([string]$File)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Loading host queue from $File."
    $queue = @{}
    if (-not (Test-Path -Path $File)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Queue file not found. Creating empty $File."
        New-Item -ItemType File -Path $File -Force | Out-Null
        return $queue
    } 
    
    $content = Get-Content -Path $File -ErrorAction SilentlyContinue
    if ($null -eq $content -or $content.Count -eq 0) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Queue file is empty."
        return $queue
    }

    $content | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_)) {
            $parts = $_ -split ','
            if ($parts.Length -ge 2) {
                $RemoteHost = $parts[0].Trim()
                if (-not [string]::IsNullOrWhiteSpace($RemoteHost)) {
                    try {
                        $timeStamp = [datetime]::Parse($parts[1])
                        $queue[$RemoteHost] = $timeStamp
                    } catch {
                        Write-Warning ("[{0}] Invalid timestamp for host '{1}': '{2}'" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $RemoteHost, $parts[1])
                    }
                }
            }
        }
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Host queue loaded with $($queue.Count) entries."
    return $queue
}

function Save-HostQueue {
    param(
        [hashtable]$Queue,
        [string]$File
    )
    if ($null -eq $Queue) { return }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Saving host queue to $File."
    $lines = $Queue.GetEnumerator() | ForEach-Object { "{0},{1}" -f $_.Key, $_.Value.ToString('o') }
    $lines | Out-File -FilePath $File -Force -Encoding utf8
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Host queue saved."
}

function Get-TargetHosts {
    param([string]$File)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Getting target hosts from $File."
    if (-not (Test-Path -Path $File)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Hosts file not found. Creating empty $File."
        New-Item -ItemType File -Path $File -Force | Out-Null
        return @()
    }
    
    $content = Get-Content -Path $File -ErrorAction SilentlyContinue
    if ($null -eq $content) {
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed to read $File or file is empty."
        return @()
    }
    
    $validHosts = $content | 
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$' }
    
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Found $($validHosts.Count) valid hosts in $File."
    if ($validHosts.Count -eq 0) {
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] No valid hosts found in $File. Add valid hostnames and rerun."
    }
    return $validHosts
}

function Should-ProcessHost {
    param(
        [string]$RemoteHost,
        [hashtable]$Queue,
        [int]$QueueDuration
    )
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Checking if $RemoteHost should be processed."
    
    # Always ensure we have a valid queue hashtable
    if ($null -eq $Queue) {
        $Queue = @{}
    }
    
    # If SkipQueue or ForceRetry is enabled, always process
    if ($SkipQueue -or $ForceRetry) {
        $reason = if ($SkipQueue) { "Skip queue" } else { "Force retry" }
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $reason enabled for $RemoteHost."
        if ($Queue.ContainsKey($RemoteHost)) {
            $Queue.Remove($RemoteHost)
        }
        return $true
    }

    if ($Queue.ContainsKey($RemoteHost)) {
        $queuedTime = $Queue[$RemoteHost]
        $elapsed = ((Get-Date) - $queuedTime).TotalSeconds
        $remainingMinutes = [math]::Round(($QueueDuration - $elapsed) / 60)
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $RemoteHost is in queue. Elapsed time: $elapsed seconds (Remaining: $remainingMinutes minutes)."
        
        if ($elapsed -lt $QueueDuration) {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping $RemoteHost (retry in $remainingMinutes minutes)."
            return $false
        } else {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Removing $RemoteHost from queue (retry duration met)."
            $Queue.Remove($RemoteHost)
            return $true
        }
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $RemoteHost is not in queue. Proceeding."
    return $true
}

function Test-HostConnectivity {
    param([string]$RemoteHost)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Testing connectivity to $RemoteHost."
    $result = Test-Connection -ComputerName $RemoteHost -Count 1 -Quiet
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connectivity test result for ${RemoteHost}: ${result}"
    return $result
}

function Should-SkipUpdate {
    param(
        [object]$HostData,
        [int]$SkipDays
    )
    if ($null -eq $HostData.last_successful_update_timestamp -or $HostData.last_successful_update_timestamp -eq '') {
        return $false
    }
    try {
        $lastUpdate = [datetime]::Parse($HostData.last_successful_update_timestamp)
        $age = (Get-Date) - $lastUpdate
        return $age.TotalDays -lt $SkipDays
    } catch {
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Error parsing timestamp for $($HostData.hostname): $_"
        return $false
    }
}

function Update-HostData {
    param(
        [hashtable]$YamlData,
        [string]$Hostname,
        [boolean]$UpdateSuccess,
        [string]$UpdateTimestamp = $null,
        [string]$ConnectionTimestamp = $null
    )
    $hostEntry = $YamlData.systems | Where-Object { $_.hostname -eq $Hostname }
    if (-not $hostEntry) {
        $hostEntry = @{
            hostname                      = $Hostname
            last_connection_timestamp    = $ConnectionTimestamp
            last_successful_update_timestamp = $UpdateTimestamp
            update_success                = $UpdateSuccess
            reboot                        = $false
        }
        $YamlData.systems += $hostEntry
    } else {
        if ($ConnectionTimestamp) { $hostEntry.last_connection_timestamp = $ConnectionTimestamp }
        if ($UpdateTimestamp) { $hostEntry.last_successful_update_timestamp = $UpdateTimestamp }
        $hostEntry.update_success = $UpdateSuccess
    }
}

function Invoke-RemoteUpdate {
    param(
        [string]$RemoteHost,
        [string]$PsExecPath,
        [switch]$AutoReboot,
        [int]$SkipDays
    )

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting remote update on $RemoteHost."

    if ([string]::IsNullOrEmpty($RemoteHost)) {
        Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Remote host name is empty"
        return [pscustomobject]@{
            RemoteHost = $RemoteHost
            ExitCode = 1
            StdOut = "Error: Remote host name is empty"
            StdErr = "Invalid remote host parameter"
        }
    }

    # Get local host name for UNC path
    $localHost = $env:COMPUTERNAME

    # Define paths
    $remoteScriptPath = "\\$localHost\C$\Tools\Git\Win2Update\UpdateScriptv1.ps1"
    $remoteLogPath = "%TEMP%\RemoteUpdate\$RemoteHost-$(Get-Date -Format 'yyyyMMddHHmmss').log"

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Executing update script on $RemoteHost..."

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $PsExecPath
    $processInfo.Arguments = "-nobanner -accepteula -h \\$RemoteHost powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteScriptPath`" -LogPath `"$remoteLogPath`" -AutoReboot:$AutoReboot"
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false

    try {
        $process = [System.Diagnostics.Process]::Start($processInfo)
        if (-not $process) {
            throw "Failed to start PsExec process for execution"
        }

        # Read output streams asynchronously to prevent deadlocks
        $stdOutTask = $process.StandardOutput.ReadToEndAsync()
        $stdErrTask = $process.StandardError.ReadToEndAsync()

        # Reduced timeout to 15 minutes for quicker failure detection
        if (-not $process.WaitForExit(900000)) { # 15 minute timeout
            Write-Warning "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Process timeout for $RemoteHost after 15 minutes, attempting to terminate..."
            try {
                $process.Kill()
            } catch {
                Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed to terminate process: $_"
            }
            throw "Process timed out after 15 minutes"
        }

        $stdOut = $stdOutTask.Result
        $stdErr = $stdErrTask.Result

        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] PsExec completed on $RemoteHost with ExitCode=$($process.ExitCode)"
    } catch {
        Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Process execution error: $_"
        $stdOut = "Error: Process execution failed"
        $stdErr = $_.Exception.Message
        return [pscustomobject]@{
            RemoteHost = $RemoteHost
            ExitCode   = 1
            StdOut     = $stdOut
            StdErr     = $stdErr
        }
    }

    # Optional: Retrieve remote log for debugging (if accessible)
    # This could be added later if needed for better diagnostics

    return [pscustomobject]@{
        RemoteHost = $RemoteHost
        ExitCode   = $process.ExitCode
        StdOut     = $StdOut
        StdErr     = $StdErr
    }
}

# Function to clear retry queue
function Clear-RetryQueue {
    param([string]$QueueFile)
    if (Test-Path $QueueFile) {
        Remove-Item $QueueFile -Force
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Cleared retry queue."
    }
    return @{}
}

# Initialize log paths and ensure directories exist
$logsDir = Join-Path -Path $PSScriptRoot -ChildPath '.logs'
if (-not (Test-Path -Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# Set default file paths if not provided
if (-not $ErrorLogFile) {
    $ErrorLogFile = Join-Path -Path $logsDir -ChildPath 'error.log'
}
$errorLog = $ErrorLogFile
$successLog = [System.IO.Path]::ChangeExtension($errorLog, '.success.log')

# Initialize the log files if they don't exist
if (-not (Test-Path -Path $errorLog)) {
    New-Item -ItemType File -Path $errorLog -Force | Out-Null
    Set-Content -Path $errorLog -Value "[]" -Force
}
if (-not (Test-Path -Path $successLog)) {
    New-Item -ItemType File -Path $successLog -Force | Out-Null
    Set-Content -Path $successLog -Value "[]" -Force
}

# Set default paths for other files if not provided
if (-not $YamlFile) { 
    $YamlFile = Join-Path -Path $PSScriptRoot -ChildPath 'hosts_tracking.yaml'
}
if (-not $QueueFile) { 
    $QueueFile = Join-Path -Path $PSScriptRoot -ChildPath 'hostQueue.txt'
}
if (-not $HostsFile) { 
    $HostsFile = Join-Path -Path $PSScriptRoot -ChildPath 'hosts.txt'
}

# Clear retry queue if force retry is enabled
if ($ForceRetry) {
    $hostQueue = Clear-RetryQueue -QueueFile $QueueFile
}

# Load data
$yamlData = Load-YamlData -File $YamlFile
$updateQueue = Load-HostQueue -File $QueueFile
$targetMachines = Get-TargetHosts -File $HostsFile
if (-not $targetMachines -or $targetMachines.Count -eq 0) {
    Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] No hosts provided. Exiting."
    return
}

# Initialize YAML if empty
if ($yamlData.systems.Count -eq 0) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initializing YAML with host list."
    foreach ($machine in $targetMachines) {
        Update-HostData -YamlData $yamlData -Hostname $machine -UpdateSuccess $false -ConnectionTimestamp $null -UpdateTimestamp $null
    }
    Save-YamlData -Data $yamlData -File $YamlFile
}

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting update process for $($targetMachines.Count) host(s)..."

if ($Debug) {
    Write-Host "[DEBUG] Queue status:"
    Write-Host "[DEBUG] SkipQueue: $SkipQueue"
    Write-Host "[DEBUG] ForceRetry: $ForceRetry"
    Write-Host "[DEBUG] Current queue entries: $($updateQueue.Count)"
    if ($updateQueue -and $updateQueue.Count -gt 0) {
        $updateQueue.Keys | ForEach-Object { 
            Write-Host "[DEBUG] - $_ : $($updateQueue[$_])"
        }
    }
}

foreach ($targetSystem in $targetMachines) {
    Write-Host "`n[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Processing host: $targetSystem"
    Write-Host "=================================================="

    if ($Debug) {
        Write-Host "[DEBUG] Checking host processing conditions:"
        Write-Host "[DEBUG] - In Queue: $($updateQueue.ContainsKey($targetSystem))"
        Write-Host "[DEBUG] - SkipQueue: $SkipQueue"
        Write-Host "[DEBUG] - ForceRetry: $ForceRetry"
    }

    # Queue check
    if (-not (Should-ProcessHost -RemoteHost $targetSystem -Queue $updateQueue -QueueDuration $QueueDuration)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping $targetSystem (in retry queue)."
        continue
    }

    # Connectivity
    if (-not (Test-HostConnectivity -RemoteHost $targetSystem)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Unreachable: $targetSystem (queued for retry)."
        Update-HostData -YamlData $yamlData -Hostname $targetSystem -UpdateSuccess $false
        Save-YamlData -Data $yamlData -File $YamlFile
        $updateQueue[$targetSystem] = Get-Date
        Write-StructuredLog -RemoteHost $targetSystem -Status 'Unreachable' -Message 'Host unreachable' -LogFile $errorLog
        continue
    }

    # Update connection
    $connectionTimestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
    Update-HostData -YamlData $yamlData -Hostname $targetSystem -UpdateSuccess $false -ConnectionTimestamp $connectionTimestamp
    Save-YamlData -Data $yamlData -File $YamlFile

    # Check host data for skip
    $systemData = $yamlData.systems | Where-Object { $_.hostname -eq $targetSystem }
    if (Should-SkipUpdate -HostData $systemData -SkipDays $SkipDays) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping $targetSystem (updated recently)."
        Update-HostData -YamlData $yamlData -Hostname $targetSystem -UpdateSuccess $true
        Save-YamlData -Data $yamlData -File $YamlFile
        Write-StructuredLog -RemoteHost $targetSystem -Status 'Skipped' -Message 'Recently updated' -LogFile $successLog
        continue
    }

    # Determine reboot flag
    $rebootFlag = $systemData.reboot -as [boolean]

    # Perform update
    $res = Invoke-RemoteUpdate -RemoteHost $targetSystem -PsExecPath $PsExecPath -AutoReboot:$AutoReboot -SkipDays $SkipDays
    if ($res.ExitCode -eq 0) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SUCCESS: $targetSystem update completed."
        $updateTimestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Update-HostData -YamlData $yamlData -Hostname $targetSystem -UpdateSuccess $true -UpdateTimestamp $updateTimestamp
        Write-StructuredLog -RemoteHost $targetSystem -Status 'Success' -Message ($res.StdOut.Trim()) -LogFile $successLog
    } else {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $targetSystem update failed."
        $msg = if ($res.StdErr) { $res.StdErr.Trim() } else { $res.StdOut.Trim() }
        Update-HostData -YamlData $yamlData -Hostname $targetSystem -UpdateSuccess $false
        $updateQueue[$targetSystem] = Get-Date
        Write-StructuredLog -RemoteHost $targetSystem -Status 'Error' -Message $msg -LogFile $errorLog
    }
    Save-YamlData -Data $yamlData -File $YamlFile
}

Save-HostQueue -Queue $hostQueue -File $QueueFile

# Generate detailed summary
$timestamp = Get-StandardTimestamp
Write-Host "`n=== Update Process Summary ($timestamp) ==="
Write-Host "----------------------------------------"

# Calculate statistics
function Get-LogStatistics {
    param([string]$LogFile, [string]$Status = $null)
    
    try {
        if (Test-Path -Path $LogFile) {
            $logs = Get-Content -Path $LogFile -Raw | ConvertFrom-Json
            if ($Status) {
                return @($logs | Where-Object Status -eq $Status).Count
            }
            return @($logs).Count
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Warning "Failed to read log statistics from ${LogFile}: $errorMsg"
    }
    return 0
}

$successCount = Get-LogStatistics -LogFile $successLog -Status 'Success'
$skipCount = Get-LogStatistics -LogFile $successLog -Status 'Skipped'
$errorCount = Get-LogStatistics -LogFile $errorLog

$queuedCount = $hostQueue.Count

# Display summary
Write-Host "Total Hosts Processed: $($targetMachines.Count)"
Write-Host "Successful Updates:    $successCount"
Write-Host "Skipped (Recent):      $skipCount"
Write-Host "Failed/Unreachable:    $errorCount"
Write-Host "Queued for Retry:      $queuedCount"
Write-Host "----------------------------------------"

# Display retry queue if not empty
if ($queuedCount -gt 0) {
    Write-Host "`nHosts in retry queue:"
    $hostQueue.GetEnumerator() | ForEach-Object {
        $waitTime = [math]::Round(($QueueDuration - ((Get-Date) - $_.Value).TotalSeconds))
        if ($waitTime -gt 0) {
            Write-Host "  $($_.Key) - Retry in $([math]::Round($waitTime/60)) minutes"
        }
    }
}

Write-Host "`nLogs:"
Write-Host "  Success Log: $successLog"
Write-Host "  Error Log:   $errorLog"
Write-Host "  Debug Logs:  $logsDir"

Read-Host "`nPress Enter to exit"
