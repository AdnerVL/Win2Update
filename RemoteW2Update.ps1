# Ensure script runs elevated
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Script must run as Administrator. Exiting."
    exit 1
}

$scriptDir = $PSScriptRoot
$hostsFile = Join-Path -Path $scriptDir -ChildPath "hosts.txt"
$queueFile = Join-Path -Path $scriptDir -ChildPath "hostQueue.txt"
$logFile = Join-Path -Path $scriptDir -ChildPath "errorLog.txt"
$queueDuration = 3 * 60 * 60

$hostQueue = @{}
if (Test-Path -Path $queueFile) {
    $queuedData = Get-Content -Path $queueFile | ForEach-Object {
        $hostName, $timeStamp = $_ -split ','
        [PSCustomObject]@{ Host = $hostName; TimeStamp = [DateTime]::Parse($timeStamp) }
    }
    $queuedData | ForEach-Object { $hostQueue[$_.Key] = $_.Value }
}

if (Test-Path -Path $hostsFile) {
    $hosts = Get-Content -Path $hostsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
} else {
    $userInput = Read-Host "Enter hostnames (space-separated)"
    $hosts = ($userInput.Trim() -split '\s+') | Where-Object { $_ -ne "" }
}

if ($hosts.Count -eq 0) {
    Write-Error "No hosts provided. Exiting."
    exit 1
}

# Configure local WinRM service
$winrmService = Get-Service -Name WinRM
if ($winrmService.Status -ne 'Running') {
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
    Start-Service -Name WinRM -ErrorAction Stop
}
if (-not (Test-Path WSMan:\localhost\Client\TrustedHosts)) {
    Set-WSManQuickConfig -Force -ErrorAction Stop
}

# Add hosts to local TrustedHosts
$existingTrustedHosts = try { (Get-Item WSMan:\localhost\Client\TrustedHosts).Value } catch { "" }
$hostsToAdd = $hosts -join ','
if ($existingTrustedHosts) {
    $hostsToAdd = "$existingTrustedHosts,$hostsToAdd"
}
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $hostsToAdd -Force

foreach ($targetHost in $hosts) {
    if ($hostQueue.ContainsKey($targetHost)) {
        $queuedTime = $hostQueue[$targetHost]
        if (((Get-Date) - $queuedTime).TotalSeconds -lt $queueDuration) {
            continue
        } else {
            $hostQueue.Remove($targetHost)
            ($hostQueue.GetEnumerator() | ForEach-Object { "$($_.Key),$($_.Value)" }) | Out-File -FilePath $queueFile -Force
        }
    }

    if (-not (Test-Connection -ComputerName $targetHost -Count 1 -Quiet)) {
        $hostQueue[$targetHost] = Get-Date
        ($hostQueue.GetEnumerator() | ForEach-Object { "$($_.Key),$($_.Value)" }) | Out-File -FilePath $queueFile -Force
        continue
    }

    if (-not (Test-WSMan -ComputerName $targetHost -ErrorAction SilentlyContinue)) {
        try {
            .\PsExec.exe \\$targetHost -h powershell.exe -Command {
                $ErrorActionPreference = 'Stop'
                $winrmService = Get-Service -Name WinRM
                if ($winrmService.Status -ne 'Running') {
                    Set-Service -Name WinRM -StartupType Automatic
                    Start-Service -Name WinRM
                }
                Enable-PSRemoting -Force
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$using:targetHost" -Force
            }
        } catch {
            Write-Error "PSRemoting setup failed on ${targetHost}: $($_.Exception.Message)"
            "$(Get-Date): PSRemoting setup failed on ${targetHost}: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
            continue
        }
    }

    try {
        Invoke-Command -ComputerName $targetHost -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Repository PSGallery
            Import-Module PSWindowsUpdate
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                $wingetInstallerUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
                $wingetInstallerPath = "$env:TEMP\winget.msixbundle"
                Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile $wingetInstallerPath -UseBasicParsing
                Add-AppxPackage -Path $wingetInstallerPath
            }
            winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements --force
            Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
        }
    } catch {
        Write-Error "Command execution failed on ${targetHost}: $($_.Exception.Message)"
        "$(Get-Date): Command execution failed on ${targetHost}: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        continue
    }
}