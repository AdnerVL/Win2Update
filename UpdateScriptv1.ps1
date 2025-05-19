# Check for elevated permissions
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isElevated) {
    # Relaunch as elevated with execution policy bypass
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Wait
    exit
}

# Define the path for the transcript log
$logPath = 'C:\Tools\UpdateLog.txt'
$logDir = Split-Path $logPath -Parent

# Ensure the log directory exists
if (-not $logDir -or -not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop
}

Start-Transcript -Path $logPath -Append -Force

try {
    # Set execution policy for the session
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

    # Unload conflicting modules
    if (Get-Module -Name PackageManagement) {
        Remove-Module -Name PackageManagement -Force -ErrorAction SilentlyContinue
    }
    if (Get-Module -Name PSWindowsUpdate) {
        Remove-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
    }

    # Install necessary package providers and modules
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false
    Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
    Import-Module -Name PSWindowsUpdate

    # Configure Windows Update settings
    Write-Host "Configuring Windows Update..."
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false

    # Perform Windows Updates
    Write-Host "Installing Windows Updates..."
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot

    # Perform application upgrades using winget
    Write-Host "Upgrading applications with winget..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements | Out-File -FilePath $logPath -Append
    } else {
        Write-Warning "winget not found."
    }

} catch {
    Write-Error "Error: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
} finally {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Default -Force -ErrorAction SilentlyContinue
    Stop-Transcript
    # Check and perform reboot if required
    if (Get-WURebootStatus -Silent) {
        Write-Host "Reboot required. Initiating reboot..."
        Restart-Computer -Force
    } else {
        Write-Host "No reboot needed."
    }
}