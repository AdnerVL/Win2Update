# Ensure script runs with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Script must run as Administrator. Exiting."
    exit 1
}

# Set script directory and key file paths
$scriptDir = $PSScriptRoot
$hostsFile = Join-Path -Path $scriptDir -ChildPath "hosts.txt"           # List of target hosts
$queueFile = Join-Path -Path $scriptDir -ChildPath "hostQueue.txt"      # Hosts queued for retry
$logFile = Join-Path -Path $scriptDir -ChildPath "errorLog.txt"         # Error log for failures
$queueDuration = 3 * 60 * 60                                              # Queue retry duration (in seconds)

# Load or initialize the host queue (for retrying unreachable hosts)
$hostQueue = @{}
if (Test-Path -Path $queueFile) {
    $queuedData = Get-Content -Path $queueFile | ForEach-Object {
        $hostName, $timeStamp = $_ -split ','
        [PSCustomObject]@{ Host = $hostName; TimeStamp = [DateTime]::Parse($timeStamp) }
    }
    $queuedData | ForEach-Object { $hostQueue[$_.Key] = $_.Value }
}

# Helper function to update the queue file
function Update-QueueFile {
    param($queue, $file)
    ($queue.GetEnumerator() | ForEach-Object { "$($_.Key),$($_.Value)" }) -join "`n" | Out-File -FilePath $file -Force
}

# Load hosts from file or prompt user for input
if (Test-Path -Path $hostsFile) {
    $hosts = Get-Content -Path $hostsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
} else {
    $userInput = Read-Host "Enter hostnames (space-separated)"
    $hosts = ($userInput.Trim() -split '\s+') | Where-Object { $_ -ne "" }
}

# Exit if no hosts are provided
if ($hosts.Count -eq 0) {
    Write-Error "No hosts provided. Exiting."
    exit 1
}

# Main loop: process each target host
foreach ($targetHost in $hosts) {
    Write-Host "Processing host: $targetHost"
    # Skip hosts still in the retry queue (within queue duration)
    if ($hostQueue.ContainsKey($targetHost)) {
        $queuedTime = $hostQueue[$targetHost]
        if (((Get-Date) - $queuedTime).TotalSeconds -lt $queueDuration) {
            Write-Host "  Skipping (in retry queue): $targetHost"
            continue
        } else {
            # Remove from queue if retry time has passed
            $hostQueue.Remove($targetHost)
            Update-QueueFile $hostQueue $queueFile
        }
    }

    # Test connectivity to host; queue if unreachable
    if (-not (Test-Connection -ComputerName $targetHost -Count 1 -Quiet)) {
        Write-Host "  Unreachable: $targetHost (queued for retry)"
        $hostQueue[$targetHost] = Get-Date
        Update-QueueFile $hostQueue $queueFile
        continue
    }

    try {
        # Use PsExec to run the update/upgrade block as SYSTEM/admin on the remote host
        # This ensures all update actions run with full privileges and avoids UAC/PSRemoting issues
        .\PsExec.exe \\$targetHost -h powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            # Set strict error handling
            $ErrorActionPreference = 'Stop'

            # Set execution policy to allow module installation (for this user only)
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

            # Ensure PowerShellGet is available for module management
            if (-not (Get-Module -Name PowerShellGet -ListAvailable)) {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
                Install-Module -Name PowerShellGet -Force -Scope CurrentUser -Repository PSGallery
            }
            Import-Module PowerShellGet

            # Install and import PSWindowsUpdate module for Windows Update management
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Repository PSGallery
            Import-Module PSWindowsUpdate

            # Run Windows Update (no reboot)
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot

            # Ensure winget is available, install if missing
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                $wingetInstallerUrl = 'https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                $wingetInstallerPath = "$env:TEMP\winget.msixbundle"
                Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile $wingetInstallerPath -UseBasicParsing
                Add-AppxPackage -Path $wingetInstallerPath
            }

            # Upgrade all available packages via winget
            winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements --force

            # Trigger MDM app update scan (for managed environments)
            Get-CimInstance -Namespace 'Root\\cimv2\\mdm\\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' | Invoke-CimMethod -MethodName UpdateScanMethod
        "
        Write-Host "  SUCCESS: $targetHost update completed."
        "$(Get-Date): SUCCESS: $targetHost update completed." | Out-File -FilePath $logFile -Append
    } catch {
        # Log and skip host if remote command fails (network, permissions, or update errors)
        Write-Host "  ERROR: $targetHost update failed: $($_.Exception.Message)"
        Write-Error "Command execution failed on ${targetHost}: $($_.Exception.Message)"
        "$(Get-Date): Command execution failed on ${targetHost}: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        continue
    }
}