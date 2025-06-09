# Windows Update and Software Upgrade Script
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path (Split-Path $_ -Parent) -PathType Container })]
    [string]$LogPath,
    [Parameter(Mandatory=$false)]
    [switch]$AutoReboot
)

$ErrorActionPreference = 'Stop'

function Test-AdminRights {
    $principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

try {
    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    if (Test-Path $LogPath) { Remove-Item $LogPath -Force }
    Start-Transcript -Path $LogPath -Force
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Script started" | Out-Host
} catch {
    Write-Error "Failed to initialize logging: $_"
    exit 1
}

function Get-PendingUpdates {
    try {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking for available Windows updates..." | Out-Host
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Search("IsInstalled=0").Updates
    } catch {
        Write-Error "Error checking for updates: $_"
        @()
    }
}

try {
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking system status..." | Out-Host
    
    $isAdmin = Test-AdminRights
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Running with administrator rights: $isAdmin" | Out-Host
    
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking and installing app updates via winget..." | Out-Host
        $wingetOutput = winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements --force 2>&1
        Write-Output $wingetOutput | Tee-Object -FilePath "$LogPath.winget" -Append | Out-Host
        if ($LASTEXITCODE -eq 0 -and $wingetOutput -notmatch "No applicable updates") {
            # Verify installation by checking version
            $wingetList = winget list --id DuoSecurity.Duo2FAAuthenticationforWindows 2>&1
            if ($wingetList -match "5.1.1.1102") {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget updates installed and verified" | Out-Host
            } else {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget updates may not have installed correctly" | Out-Host
            }
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No winget updates applied or installation failed" | Out-Host
        }
    } else {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget not found. Skipping app updates." | Out-Host
    }
    
    if ($isAdmin) {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Starting Windows Update operations..." | Out-Host
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Installing PSWindowsUpdate module..." | Out-Host
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        
        $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
        if ($updates.Count -gt 0) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Installing $($updates.Count) updates..." | Out-Host
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No Windows updates available" | Out-Host
        }
        
        if (Get-WURebootStatus -Silent) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): System restart required" | Out-Host
            if ($AutoReboot) {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Initiating system restart..." | Out-Host
                Restart-Computer -Force
            } else {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Reboot required but AutoReboot not set." | Out-Host
            }
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No reboot needed" | Out-Host
        }
    } else {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Skipping Windows Update operations (no admin rights)" | Out-Host
    }

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Operations completed successfully" | Out-Host
} catch {
    Write-Error "Error: $_"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
} finally {
    Stop-Transcript
}