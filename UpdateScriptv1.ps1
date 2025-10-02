# Windows Update and Software Upgrade Script
param(
    [Parameter(Mandatory)]
    [string]$LogPath
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
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Script started"
} catch {
    Write-Error "Failed to initialize logging: $_"
    exit 1
}

function Get-PendingUpdates {
    try {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking for available Windows updates..."
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Search("IsInstalled=0").Updates
    } catch {
        Write-Error "Error checking for updates: $_"
        @()
    }
}

try {
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking system status..."
    
    $isAdmin = Test-AdminRights
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Running with administrator rights: $isAdmin"
    
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Checking and installing app updates via winget..."
        $wingetOutput = winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements --force 2>&1
        Write-Output $wingetOutput | Tee-Object -FilePath "$LogPath.winget" -Append
        if ($LASTEXITCODE -eq 0 -and $wingetOutput -notmatch "No applicable updates") {
            # Verify installation by checking version
            $wingetList = winget list --id DuoSecurity.Duo2FAAuthenticationforWindows 2>&1
            if ($wingetList -match "5.1.1.1102") {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget updates installed and verified"
            } else {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget updates may not have installed correctly"
            }
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No winget updates applied or installation failed"
        }
    } else {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Winget not found. Skipping app updates."
    }
    
    if ($isAdmin) {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Starting Windows Update operations..."
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Installing PSWindowsUpdate module..."
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        
        $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
        if ($updates.Count -gt 0) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Installing $($updates.Count) updates..."
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No Windows updates available"
        }
        
        if (Get-WURebootStatus -Silent) {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): System restart required"
            if ($AutoReboot) {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Initiating system restart..."
                Restart-Computer -Force
            } else {
                Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Reboot required but AutoReboot not set."
            }
        } else {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): No reboot needed"
        }
    } else {
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Skipping Windows Update operations (no admin rights)"
    }

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Operations completed successfully"
} catch {
    Write-Error "Error: $_"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
} finally {
    Stop-Transcript
}