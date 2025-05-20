@echo off
setlocal EnableDelayedExpansion

:: ====================================================
:: Windows Update and Software Upgrade Script
:: ====================================================
echo ====================================================
echo Windows Update and Software Upgrade Script
echo ====================================================
echo This script will:
echo  - Update Windows using the PSWindowsUpdate module
echo  - Upgrade installed applications using winget
echo  - Reboot if required
echo  - Create detailed logs of all operations
echo ====================================================

where powershell >nul 2>&1
if errorlevel 1 (
    echo Error: PowerShell is required but not found.
    pause
    exit /b 1
)

for /f %%a in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "LogDateTime=%%a"

set "LogDir=C:\Tools\Logs"
if not exist "!LogDir!" (
    mkdir "!LogDir!" 2>nul
    if errorlevel 1 (
        set "LogDir=%TEMP%"
    )
)
echo test > "!LogDir!\test.tmp" 2>nul
if errorlevel 1 (
    set "LogDir=%TEMP%"
)
del "!LogDir!\test.tmp" 2>nul

set "LogFile=!LogDir!\UpdateAllLog_%LogDateTime%.txt"
echo %DATE% %TIME% - [BATCH] Starting batch script > "!LogFile!"

echo %DATE% %TIME% - [BATCH] Checking for administrator privileges >> "!LogFile!"
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\elevate.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\elevate.vbs"
    cscript //nologo "%TEMP%\elevate.vbs" >nul 2>&1
    del "%TEMP%\elevate.vbs" 2>nul
    exit /b
) else (
    echo %DATE% %TIME% - [BATCH] Running with administrator privileges >> "!LogFile!"
)

echo test > test.tmp 2>> "!LogFile!"
if errorlevel 1 (
    echo Error: Cannot write to %CD%.
    pause
    exit /b 1
) else (
    del test.tmp
    echo %DATE% %TIME% - [BATCH] Write permissions confirmed >> "!LogFile!"
)

ping -n 1 -w 1000 8.8.8.8 >nul 2>&1
if errorlevel 1 (
    echo Warning: No internet connectivity detected.
    choice /C YN /M "Continue anyway?"
    if errorlevel 2 exit /b 1
) else (
    echo %DATE% %TIME% - [BATCH] Internet connectivity confirmed >> "!LogFile!"
)

set "PSLogFile=!LogDir!\PSUpdateLog_%LogDateTime%.txt"
set "PSScriptPath=%~dp0UpdateScript_%RANDOM%.ps1"

:: Build PowerShell script
echo. > "!PSScriptPath!"
>> "!PSScriptPath!" echo param([string]$LogPath)
>> "!PSScriptPath!" echo $ErrorActionPreference = 'Stop'
>> "!PSScriptPath!" echo $ProgressPreference = 'SilentlyContinue'
>> "!PSScriptPath!" echo Start-Transcript -Path $LogPath -Append -Force
>> "!PSScriptPath!" echo try {
>> "!PSScriptPath!" echo     [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
>> "!PSScriptPath!" echo     Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
>> "!PSScriptPath!" echo     Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
>> "!PSScriptPath!" echo     if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
>> "!PSScriptPath!" echo         Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
>> "!PSScriptPath!" echo     }
>> "!PSScriptPath!" echo     Import-Module PSWindowsUpdate
>> "!PSScriptPath!" echo     Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
>> "!PSScriptPath!" echo     $updates = Get-WindowsUpdate -MicrosoftUpdate
>> "!PSScriptPath!" echo     if ($updates.Count -gt 0) {
>> "!PSScriptPath!" echo         Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
>> "!PSScriptPath!" echo     } else {
>> "!PSScriptPath!" echo         Write-Host "No updates available"
>> "!PSScriptPath!" echo     }
>> "!PSScriptPath!" echo     if (Get-Command winget -ErrorAction SilentlyContinue) {
>> "!PSScriptPath!" echo         winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements
>> "!PSScriptPath!" echo     } else {
>> "!PSScriptPath!" echo         Write-Host "winget not found. Skipping app upgrades."
>> "!PSScriptPath!" echo     }
>> "!PSScriptPath!" echo     Write-Host "Checking if reboot is required..."
>> "!PSScriptPath!" echo     if ((Get-WURebootStatus -Silent) -eq $true) {
>> "!PSScriptPath!" echo         $choice = Read-Host "Updates complete. Reboot required. Reboot now? (Y/N)"
>> "!PSScriptPath!" echo         if ($choice -eq 'Y' -or $choice -eq 'y') {
>> "!PSScriptPath!" echo             Write-Host "Rebooting system..."
>> "!PSScriptPath!" echo             Restart-Computer -Force
>> "!PSScriptPath!" echo         } else {
>> "!PSScriptPath!" echo             Write-Host "Reboot skipped by user."
>> "!PSScriptPath!" echo         }
>> "!PSScriptPath!" echo     } else {
>> "!PSScriptPath!" echo         Write-Host "No reboot needed."
>> "!PSScriptPath!" echo     }
>> "!PSScriptPath!" echo } catch {
>> "!PSScriptPath!" echo     Write-Host "Error: $($_.Exception.Message)"
>> "!PSScriptPath!" echo } finally {
>> "!PSScriptPath!" echo     Stop-Transcript
>> "!PSScriptPath!" echo }

if not exist "!PSScriptPath!" (
    echo Error: PowerShell script creation failed.
    pause
    exit /b 1
)

echo %DATE% %TIME% - [BATCH] Running PowerShell update script >> "!LogFile!"
powershell -NoProfile -ExecutionPolicy Bypass -File "!PSScriptPath!" -LogPath "!PSLogFile!" >> "!LogFile!" 2>&1
set "PS_EXIT_CODE=%ERRORLEVEL%"

:: Cleanup
if %PS_EXIT_CODE% NEQ 0 (
    echo %DATE% %TIME% - [BATCH] PowerShell script failed with exit code %PS_EXIT_CODE% >> "!LogFile!"
    echo PowerShell script failed. See:
    echo - Batch Log: !LogFile!
    echo - PowerShell Log: !PSLogFile!
    echo - Script Path: !PSScriptPath!
    pause
    exit /b %PS_EXIT_CODE%
) else (
    echo %DATE% %TIME% - [BATCH] PowerShell script executed successfully >> "!LogFile!"
    del "!PSScriptPath!" 2>nul
    echo Updates completed successfully.
    echo Log files:
    echo - Batch Log: !LogFile!
    echo - PowerShell Log: !PSLogFile!
)

echo %DATE% %TIME% - [BATCH] Script finished >> "!LogFile!"
echo Done. Press any key to exit.
pause >nul
endlocal
