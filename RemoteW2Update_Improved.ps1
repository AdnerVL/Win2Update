<##
    .SYNOPSIS
        Improved version of the RemoteW2Update script with added logging for debugging.

    .DESCRIPTION
        This script automates Windows Update and application upgrades across one or more remote hosts. It includes detailed logging with timestamps to track progress and identify potential issues.
          * Configurable paths and retry intervals via parameters (no hard-coded values).
          * Modular functions for readability and testability.
          * Optional parallel execution using background jobs.
          * Structured logging for both successes and errors and a summary report at the end.
          * Download verification for winget installer (via file hash if provided).
          * Granular error handling within the remote execution block.
          * Optional reboot on remote hosts after updates.

        The default behavior mirrors the original script—processing hosts sequentially using PsExec—but administrators can tailor it as needed without editing the script itself.

    .PARAMETER HostsFile
        Path to the file containing a list of target hosts (one per line). Defaults to "hosts.txt" in the script directory.

    .PARAMETER QueueFile
        Path to the retry queue file that tracks hosts which could not be reached or where execution failed. Defaults to "hostQueue.txt" in the script directory.

    .PARAMETER ErrorLogFile
        Path to the error log file. Successes are logged to a separate file with ".success" suffix.

    .PARAMETER QueueDuration
        Time in seconds before a host is retried after a failure or unreachable status. Defaults to three hours (10,800 seconds).

    .PARAMETER MaxParallel
        Maximum number of hosts to process concurrently. When set to 1 (default), the script runs sequentially. Values greater than 1 use background jobs.

    .PARAMETER PsExecPath
        Path to PsExec.exe. By default, the script assumes PsExec is located in the same directory as the script.

    .PARAMETER AutoReboot
        When specified, remote hosts will be restarted automatically if updates require a reboot.

    .PARAMETER WingetExpectedHash
        Optional SHA256 hash of the winget installer MSIX package. When provided, the script validates the downloaded installer.

    .EXAMPLE
        .\RemoteW2Update_Improved.ps1 -HostsFile "C:\Scripts\hosts.txt" -MaxParallel 4 -AutoReboot

        Processes hosts listed in hosts.txt using up to 4 concurrent jobs and automatically reboots remote hosts when updates require it.
##>

param(
    [string]$HostsFile,
    [string]$QueueFile,
    [string]$ErrorLogFile,
    [int]$QueueDuration = 3 * 60 * 60,
    [int]$MaxParallel = 1,
    [string]$PsExecPath,
    [switch]$AutoReboot,
    [string]$WingetExpectedHash
)

# Set default file paths if not provided
if (-not $HostsFile) { $HostsFile = Join-Path -Path $PSScriptRoot -ChildPath 'hosts.txt' }
if (-not $QueueFile) { $QueueFile = Join-Path -Path $PSScriptRoot -ChildPath 'hostQueue.txt' }
if (-not $ErrorLogFile) { $ErrorLogFile = Join-Path -Path $PSScriptRoot -ChildPath 'error.log' }
if (-not $PsExecPath) { $PsExecPath = Join-Path -Path $PSScriptRoot -ChildPath 'PsExec.exe' }

# Check if running with administrative privileges
$wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
$adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$isAdmin = $prp.IsInRole($adm)

if (-not $isAdmin) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script requires administrative privileges. Attempting to elevate..."
    # Build the argument list to relaunch the script with the same parameters
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value) {
                $arguments += " -$key"
            }
        } else {
            $arguments += " -$key `"$value`""
        }
    }
    try {
        # Relaunch the script as administrator
        Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
        exit
    } catch {
        Write-Error "Failed to elevate privileges: $_"
        exit 1
    }
}

# region Helper Functions

function Write-StructuredLog {
    param(
        [string]$RemoteHost,
        [string]$Status,
        [string]$Message,
        [string]$LogFile
    )
    $entry = [PSCustomObject]@{
        Timestamp  = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        RemoteHost = $RemoteHost
        Status     = $Status
        Message    = $Message
    }
    $entry | ConvertTo-Json -Compress | Add-Content -Path $LogFile -Force
}

function Load-HostQueue {
    param([string]$File)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Loading host queue from $File"
    $queue = @{}
    if (Test-Path -Path $File) {
        Get-Content -Path $File | ForEach-Object {
            $parts = $_ -split ','
            if ($parts.Length -ge 2) {
                $RemoteHost = $parts[0]
                $timeStamp = [datetime]::Parse($parts[1])
                $queue[$RemoteHost] = $timeStamp
            }
        }
    } else {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Queue file not found: $File"
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Host queue loaded with $($queue.Count) entries"
    return $queue
}

function Save-HostQueue {
    param(
        [hashtable]$Queue,
        [string]$File
    )
    if ($null -eq $Queue) { return }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Saving host queue to $File"
    $lines = $Queue.GetEnumerator() | ForEach-Object { "{0},{1}" -f $_.Key, $_.Value.ToString('o') }
    $lines | Out-File -FilePath $File -Force -Encoding utf8
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Host queue saved"
}

function Get-TargetHosts {
    param([string]$File)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Getting target hosts from $File"
    if (Test-Path -Path $File) {
        $content = Get-Content -Path $File | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Found $($content.Count) hosts in $File"
        return $content
    } else {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Hosts file not found: $File. Prompting for input."
        $inputHosts = Read-Host "Enter hostnames (space-separated)"
        $hosts = ($inputHosts.Trim() -split '\s+') | Where-Object { $_ -ne '' }
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Received $($hosts.Count) hosts from user input"
        return $hosts
    }
}

function Should-ProcessHost {
    param(
        [string]$RemoteHost,
        [hashtable]$Queue,
        [int]$QueueDuration
    )
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Checking if $RemoteHost should be processed"
    if ($Queue.ContainsKey($RemoteHost)) {
        $queuedTime = $Queue[$RemoteHost]
        $elapsed = ((Get-Date) - $queuedTime).TotalSeconds
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $RemoteHost is in queue. Elapsed time: $elapsed seconds"
        if ($elapsed -lt $QueueDuration) {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping $RemoteHost (retry duration not met)"
            return $false
        } else {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Removing $RemoteHost from queue (retry duration met)"
            $Queue.Remove($RemoteHost)
            return $true
        }
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $RemoteHost is not in queue. Proceeding."
    return $true
}

function Test-HostConnectivity {
    param(
        [string]$RemoteHost
    )
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Testing connectivity to $RemoteHost"
    $result = Test-Connection -ComputerName $RemoteHost -Count 1 -Quiet
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connectivity test result for ${RemoteHost}: $result"
    return $result
}

function Invoke-RemoteUpdate {
    param(
        [string]$RemoteHost,
        [string]$PsExecPath,
        [switch]$AutoReboot,
        [string]$WingetExpectedHash
    )

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting remote update on $RemoteHost"

    $remoteScript = @'
        try {
            $ErrorActionPreference = "Stop"

            Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force

            if (-not (Get-Module -Name PowerShellGet -ListAvailable)) {
                try {
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop
                    Install-Module -Name PowerShellGet -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
                } catch {
                    throw "Failed to install PowerShellGet: $($_.Exception.Message)"
                }
            }
            Import-Module PowerShellGet -ErrorAction Stop

            if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
                try {
                    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
                } catch {
                    throw "Failed to install PSWindowsUpdate: $($_.Exception.Message)"
                }
            }
            Import-Module PSWindowsUpdate -ErrorAction Stop

            try {
                Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
            } catch {
                throw "Windows Update failed: $($_.Exception.Message)"
            }

            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                $wingetInstallerUrl = 'https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                $wingetInstallerPath = Join-Path -Path $env:TEMP -ChildPath 'winget.msixbundle'
                try {
                    Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile $wingetInstallerPath -UseBasicParsing -ErrorAction Stop
                } catch {
                    throw "Failed to download winget: $($_.Exception.Message)"
                }
                if ([string]::IsNullOrEmpty($using:WingetExpectedHash) -eq $false) {
                    $computedHash = (Get-FileHash -Path $wingetInstallerPath -Algorithm SHA256).Hash
                    if ($computedHash -ne $using:WingetExpectedHash) {
                        throw "Winget installer hash mismatch. Expected $($using:WingetExpectedHash), got $computedHash"
                    }
                }
                try {
                    Add-AppxPackage -Path $wingetInstallerPath -ErrorAction Stop
                } catch {
                    throw "Failed to install winget: $($_.Exception.Message)"
                }
            }

            try {
                winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements --force | Out-Null
            } catch {
                throw "winget upgrade failed: $($_.Exception.Message)"
            }

            try {
                Get-CimInstance -Namespace 'Root\\cimv2\\mdm\\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' | Invoke-CimMethod -MethodName UpdateScanMethod | Out-Null
            } catch {
                Write-Warning "Failed to trigger MDM update scan: $($_.Exception.Message)"
            }

            $needsReboot = $false
            try {
                if (Get-WURebootStatus -Silent) { $needsReboot = $true }
            } catch {
                Write-Warning "Failed to check reboot status: $($_.Exception.Message)"
            }

            if ($needsReboot -and $using:AutoReboot) {
                Restart-Computer -Force
            }

            Write-Output "Remote update completed successfully"
        } catch {
            Write-Error $_.Exception.Message
            exit 1
        }
'@

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Preparing to execute PsExec on $RemoteHost"
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName  = $PsExecPath
    $processInfo.Arguments = "-nobanner \\$RemoteHost -h powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"$remoteScript`""
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError  = $true
    $processInfo.UseShellExecute = $false

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting PsExec process on $RemoteHost"
    $process = [System.Diagnostics.Process]::Start($processInfo)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Waiting for PsExec to complete on $RemoteHost"
    $process.WaitForExit()
    $stdOut = $process.StandardOutput.ReadToEnd()
    $stdErr = $process.StandardError.ReadToEnd()
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] PsExec completed on $RemoteHost with ExitCode=$($process.ExitCode)"

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Remote update finished on $RemoteHost"

    return [pscustomobject]@{
        RemoteHost = $RemoteHost
        ExitCode   = $process.ExitCode
        StdOut     = $stdOut
        StdErr     = $stdErr
    }
}
# endregion Helper Functions

# Initialize logs
$errorLog = $ErrorLogFile
$successLog = [System.IO.Path]::ChangeExtension($errorLog, '.success.log')

# Load queue and hosts
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Loading host queue..."
$hostQueue = Load-HostQueue -File $QueueFile
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Getting target hosts..."
$hosts = Get-TargetHosts -File $HostsFile
if (-not $hosts -or $hosts.Count -eq 0) {
    Write-Error "No hosts provided. Exiting."
    return
}

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting update process for $($hosts.Count) host(s)..."

$jobs = @()

foreach ($RemoteHost in $hosts) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Processing host: $RemoteHost"
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Checking if $RemoteHost should be processed..."
    if (-not (Should-ProcessHost -RemoteHost $RemoteHost -Queue $hostQueue -QueueDuration $QueueDuration)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Skipping $RemoteHost (in retry queue)"
        continue
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Testing connectivity to $RemoteHost..."
    if (-not (Test-HostConnectivity -RemoteHost $RemoteHost)) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Unreachable: $RemoteHost (queued for retry)"
        $hostQueue[$RemoteHost] = Get-Date
        Save-HostQueue -Queue $hostQueue -File $QueueFile
        Write-StructuredLog -RemoteHost $RemoteHost -Status 'Unreachable' -Message 'Host unreachable' -LogFile $errorLog
        continue
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Invoking remote update on $RemoteHost..."
    if ($MaxParallel -gt 1) {
        # Parallel execution logic
        $jobs += Start-Job -ScriptBlock {
            param($h, $p, $auto, $hash, $errLog, $succLog)
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [Job] Starting update for $h"
            $result = Invoke-RemoteUpdate -RemoteHost $h -PsExecPath $p -AutoReboot:$auto -WingetExpectedHash $hash
            if ($result.ExitCode -eq 0) {
                Write-StructuredLog -RemoteHost $h -Status 'Success' -Message ($result.StdOut.Trim()) -LogFile $succLog
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [Job] SUCCESS: $h update completed."
            } else {
                $msg = if ($result.StdErr) { $result.StdErr } else { $result.StdOut }
                Write-StructuredLog -RemoteHost $h -Status 'Error' -Message ($msg.Trim()) -LogFile $errLog
                Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [Job] ERROR: $h update failed."
                $script:hostQueue[$h] = Get-Date
            }
        } -ArgumentList $RemoteHost, $PsExecPath, $AutoReboot, $WingetExpectedHash, $errorLog, $successLog
    } else {
        $res = Invoke-RemoteUpdate -RemoteHost $RemoteHost -PsExecPath $PsExecPath -AutoReboot:$AutoReboot -WingetExpectedHash $WingetExpectedHash
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Remote update result for ${RemoteHost}: ExitCode=$($res.ExitCode)"
        if ($res.ExitCode -eq 0) {
            Write-StructuredLog -RemoteHost $RemoteHost -Status 'Success' -Message ($res.StdOut.Trim()) -LogFile $successLog
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SUCCESS: $RemoteHost update completed."
        } else {
            $msg = if ($res.StdErr) { $res.StdErr } else { $res.StdOut }
            Write-StructuredLog -RemoteHost $RemoteHost -Status 'Error' -Message ($msg.Trim()) -LogFile $errorLog
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $RemoteHost update failed."
            $hostQueue[$RemoteHost] = Get-Date
        }
    }
}

if ($jobs.Count -gt 0) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Waiting for $($jobs.Count) job(s) to complete..."
    $jobs | Wait-Job | Out-Null
    Receive-Job -Job $jobs | Out-Null
    $jobs | Remove-Job | Out-Null
}

Save-HostQueue -Queue $hostQueue -File $QueueFile

$successCount = 0
$errorCount   = 0
if (Test-Path -Path $successLog) {
    $successCount = (Get-Content -Path $successLog).Count
}
if (Test-Path -Path $errorLog) {
    $errorCount = (Get-Content -Path $errorLog).Count
}

Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Update process completed. Successes: $successCount, Errors/Unreachable: $errorCount."