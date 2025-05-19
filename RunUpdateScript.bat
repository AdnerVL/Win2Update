@echo off
setlocal EnableDelayedExpansion

:: Script information
echo ====================================================
echo Windows Update and Software Upgrade Script
echo ====================================================
echo This script will:
echo  - Update Windows using the PSWindowsUpdate module
echo  - Upgrade installed applications using winget
echo  - Create detailed logs of all operations
echo ====================================================

:: Set log directory and file
set "LogDir=C:\Tools\Logs"
if not exist "!LogDir!" (
    mkdir "!LogDir!" 2>nul
    if errorlevel 1 (
        set "LogDir=%TEMP%"
    )
)

set "LogFile=!LogDir!\UpdateAllLog_%DATE:~-4,4%%DATE:~-7,2%%DATE:~-10,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.txt"
set "LogFile=!LogFile: =0!"

:: Start logging
echo %DATE% %TIME% - [BATCH] Starting batch script > "!LogFile!"

:: Check for admin rights and elevate if needed
echo %DATE% %TIME% - [BATCH] Checking for administrator privileges >> "!LogFile!"
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo %DATE% %TIME% - [BATCH] Not running with administrator privileges, will attempt to elevate >> "!LogFile!"
    echo This script requires administrator privileges.
    echo A UAC prompt will appear to request elevation.
    
    :: Create a VBS script to elevate the batch script
    echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\elevate.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\elevate.vbs"
    
    :: Run the VBS script to trigger UAC prompt
    cscript //nologo "%TEMP%\elevate.vbs"
    del "%TEMP%\elevate.vbs"
    
    :: Exit the non-elevated script
    exit /b
) else (
    echo %DATE% %TIME% - [BATCH] Running with administrator privileges >> "!LogFile!"
)

:: Check for write permissions in current directory
echo %DATE% %TIME% - [BATCH] Checking write permissions in %CD% >> "!LogFile!"
echo test > test.tmp 2>> "!LogFile!"
if errorlevel 1 (
    echo %DATE% %TIME% - [BATCH] Error: No write permissions in %CD% >> "!LogFile!"
    echo Error: Cannot write to %CD%. Run in a directory with write permissions.
    pause
    exit /b 1
) else (
    echo %DATE% %TIME% - [BATCH] Write permissions confirmed >> "!LogFile!"
    del test.tmp
)

:: Check for internet connectivity
echo %DATE% %TIME% - [BATCH] Checking internet connectivity >> "!LogFile!"
ping -n 1 -w 1000 8.8.8.8 >nul 2>&1
if errorlevel 1 (
    echo %DATE% %TIME% - [BATCH] Warning: No internet connectivity detected >> "!LogFile!"
    echo Warning: No internet connectivity detected. Updates may fail.
    choice /C YN /M "Do you want to continue anyway?"
    if errorlevel 2 exit /b 1
) else (
    echo %DATE% %TIME% - [BATCH] Internet connectivity confirmed >> "!LogFile!"
)

:: Set PowerShell error formatting preferences
echo %DATE% %TIME% - [BATCH] Setting PowerShell execution options >> "!LogFile!"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorView = 'CategoryView'; $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'; $ProgressPreference = 'SilentlyContinue'" >nul 2>&1

:: Set log path for PowerShell
set "PSLogFile=!LogDir!\PSUpdateLog_%DATE:~-4,4%%DATE:~-7,2%%DATE:~-10,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.txt"
set "PSLogFile=!PSLogFile: =0!"
echo %DATE% %TIME% - [BATCH] Using PowerShell log path: !PSLogFile! >> "!LogFile!"

:: Create PowerShell script in the same directory as the batch file
set "PSScriptPath=%~dp0UpdateScript_%RANDOM%.ps1"
echo %DATE% %TIME% - [BATCH] Generating PowerShell script at !PSScriptPath! >> "!LogFile!"
(
    echo # Accept LogPath parameter
    echo param(
    echo     [string]$LogPath
    echo ^)
    echo.
    echo $ErrorActionPreference = "Stop"
    echo $ProgressPreference = "SilentlyContinue"
    echo.
    echo # Define the path for the transcript log
    echo if (-not $LogPath^) {
    echo     $logPath = '!PSLogFile!'
    echo ^} else {
    echo     $logPath = $LogPath
    echo ^}
    echo $logDir = Split-Path $logPath -Parent
    echo.
    echo # Ensure the log directory exists
    echo if ^(-not $logDir -or -not ^(Test-Path $logDir^)^) {
    echo     try {
    echo         New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop ^| Out-Null
    echo     } catch {
    echo         $logPath = "$env:TEMP\PSUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    echo         Write-Warning "Could not create log directory. Using $logPath instead."
    echo     }
    echo ^}
    echo.
    echo # Centralized log function
    echo function Write-Log {
    echo     param(
    echo         [Parameter(Mandatory=$true)]
    echo         [string]$Message,
    echo         [Parameter(Mandatory=$false)]
    echo         [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
    echo         [string]$Level = "INFO"
    echo     ^)
    echo     $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    echo     $logMessage = "$timestamp - [$Level] $Message"
    echo     switch ($Level) {
    echo         "WARNING" { $foregroundColor = "Yellow" }
    echo         "ERROR"   { $foregroundColor = "Red" }
    echo         "SUCCESS" { $foregroundColor = "Green" }
    echo         default   { $foregroundColor = "White" }
    echo     }
    echo     Write-Host $logMessage -ForegroundColor $foregroundColor
    echo     try {
    echo         $logMessage ^| Out-File -FilePath $logPath -Append -ErrorAction Stopවිකලුත්තුරাই - Batch Script for Windows Updates and Software Upgrades

    :: Check for PowerShell and winget availability
    where powershell >nul 2>&1
    if errorlevel 1 (
        echo %DATE% %TIME% - [BATCH] Error: PowerShell not found >> "!LogFile!"
        echo Error: PowerShell is required but not installed.
        pause
        exit /b 1
    )

    where winget >nul 2>&1
    if errorlevel 1 (
        echo %DATE% %TIME% - [BATCH] Warning: winget not found >> "!LogFile!"
        echo Warning: winget is not installed. Application upgrades will be skipped.
    )

    :: Create PowerShell script content (abridged for brevity, same as original)
    (
        echo # Accept LogPath parameter
        echo param(
        echo     [string]$LogPath
        echo ^)
        echo.
        echo $ErrorActionPreference = "Stop"
        echo $ProgressPreference = "SilentlyContinue"
        echo.
        echo # Define the path for the transcript log
        echo if (-not $LogPath^) {
        echo     $logPath = '!PSLogFile!'
        echo ^} else {
        echo     $logPath = $LogPath
        echo ^}
        echo $logDir = Split-Path $logPath -Parent
        echo.
        echo # Ensure the log directory exists
        echo if ^(-not $logDir -or -not ^(Test-Path $logDir^)^) {
        echo     try {
        echo         New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop ^| Out-Null
        echo     } catch {
        echo economia
        echo         $logPath = "$env:TEMP\PSUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        echo         Write-Warning "Could not create log directory. Using $logPath instead."
        echo     }
        echo ^}
        echo.
        echo # Centralized log function
        echo function Write-Log {
        echo     param(
        echo         [Parameter(Mandatory=$true)]
        echo         [string]$Message,
        echo         [Parameter(Mandatory=$false)]
        echo         [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        echo         [string]$Level = "INFO"
        echo     ^)
        echo     $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        echo     $logMessage = "$timestamp - [$Level] $Message"
        echo     switch ($Level) {
        echo         "WARNING" { $foregroundColor = "Yellow" }
        echo         "ERROR"   { $foregroundColor = "Red" }
        echo         "SUCCESS" { $foregroundColor = "Green" }
        echo         default   { $foregroundColor = "White" }
        echo     }
        echo     Write-Host $logMessage -ForegroundColor $foregroundColor
        echo     try {
        echo         $logMessage ^| Out-File -FilePath $logPath -Append -ErrorAction Stop
        echo     } catch {
        echo         Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
        echo     }
        echo ^}
        echo.
        echo # Function to check if a module is available
        echo function Test-ModuleAvailable {
        echo     param([string]$ModuleName)
        echo     $module = Get-Module -Name $ModuleName -ListAvailable
        echo     return ($null -ne $module)
        echo ^}
        echo.
        echo # Function to install a module safely
        echo function Install-ModuleSafely {
        echo     param(
        echo         [string]$ModuleName,
        echo         [switch]$AllowClobber,
        echo         [int]$MaxRetries = 3
        echo     )
        echo     $retryCount = 0
        echo     $success = $false
        echo     while (-not $success -and $retryCount -lt $MaxRetries) {
        echo         try {
        echo             $params = @{
        echo                 Name = $ModuleName
        echo                 Force = $true
        echo                 Scope = "CurrentUser"
        echo                 ErrorAction = "Stop"
        echo             }
        echo             if ($AllowClobber) {
        echo                 $params.Add("AllowClobber", $true)
        echo             }
        echo             Install-Module @params
        echo             $success = $true
        echo             Write-Log "$ModuleName module installed successfully" "SUCCESS"
        echo         } catch {
        echo             $retryCount++
        echo             Write-Log "Attempt $retryCount failed to install $ModuleName: $($_.Exception.Message)" "WARNING"
        echo             if ($retryCount -ge $MaxRetries) {
        echo                 Write-Log "Failed to install $ModuleName after $MaxRetries attempts" "ERROR"
        echo                 return $false
        echo             }
        echo             Start-Sleep -Seconds ($retryCount * 5)
        echo         }
        echo     }
        echo     return $success
        echo ^}
        echo.
        echo # Check for elevated permissions
        echo Write-Log "Checking for elevated permissions"
        echo $isElevated = ^([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent^(^)^).IsInRole^([Security.Principal.WindowsBuiltInRole]::Administrator^)
        echo if ^(-not $isElevated^) {
        echo     Write-Log "Not running with administrator privileges" "ERROR"
        echo     Write-Log "This script requires administrator privileges to install updates"
        echo     exit 1
        echo ^}
        echo Write-Log "Running with administrator privileges" "SUCCESS"
        echo.
        echo try {
        echo     Write-Log "Starting transcript"
        echo     Start-Transcript -Path $logPath -Append -Force
        echo.
        echo     # Set TLS 1.2 for compatibility with newer repositories
        echo     Write-Log "Setting TLS 1.2"
        echo     [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        echo.
        echo     Write-Log "Setting execution policy to RemoteSigned"
        echo     Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
        echo     Write-Log "Execution policy set successfully" "SUCCESS"
        echo.
        echo     # Unload modules if they're already loaded to avoid conflicts
        echo     foreach ($module in @("PackageManagement", "PowerShellGet", "PSWindowsUpdate")) {
        echo         if (Get-Module -Name $module) {
        echo             Write-Log "Removing loaded $module module"
        echo             Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
        echo         }
        echo     }
        echo.
        echo     # Install NuGet package provider if necessary
        echo     if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        echo         Write-Log "Installing NuGet package provider"
        echo         Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false
        echo         Write-Log "NuGet provider installed successfully" "SUCCESS"
        echo     } else {
        echo         Write-Log "NuGet provider already installed"
        echo     }
        echo.
        echo     # Trust PSGallery if needed
        echo     if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        echo         Write-Log "Setting PSGallery as trusted repository"
        echo         Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        echo     }
        echo.
        echo     # Install modules if needed
        echo     if (-not (Test-ModuleAvailable -ModuleName "PowerShellGet")) {
        echo         Write-Log "Installing PowerShellGet module"
        echo         Install-ModuleSafely -ModuleName PowerShellGet -AllowClobber
        echo     } else {
        echo         Write-Log "PowerShellGet module already installed"
        echo     }
        echo.
        echo     if (-not (Test-ModuleAvailable -ModuleName "PSWindowsUpdate")) {
        echo         Write-Log "Installing PSWindowsUpdate module"
        echo         Install-ModuleSafely -ModuleName PSWindowsUpdate
        echo     } else {
        echo         Write-Log "PSWindowsUpdate module already installed"
        echo     }
        echo.
        echo     Write-Log "Importing PSWindowsUpdate module"
        echo     Import-Module -Name PSWindowsUpdate -ErrorAction Stop
        echo     Write-Log "PSWindowsUpdate module imported successfully" "SUCCESS"
        echo.
        echo     # Check Windows Update service status
        echo     Write-Log "Checking Windows Update service status"
        echo     $wuService = Get-Service -Name wuauserv
        echo     if ($wuService.Status -ne 'Running') {
        echo         Write-Log "Starting Windows Update service"
        echo         Start-Service -Name wuauserv
        echo     }
        echo.
        echo     Write-Log "Configuring Windows Update service"
        echo     try {
        echo         Add-WUServiceManager -MicrosoftUpdate -Confirm:$false -ErrorAction Stop
        echo         Write-Log "Windows Update service configured successfully" "SUCCESS"
        echo     } catch {
        echo         if ($_.Exception.Message -like "*already exists*") {
        echo             Write-Log "Microsoft Update service is already registered" "INFO"
        echo         } else {
        echo             Write-Log "Failed to configure Windows Update service: $($_.Exception.Message)" "ERROR"
        echo         }
        echo     }
        echo.
        echo     # Get available updates count before installing
        echo     Write-Log "Checking for available Windows Updates"
        echo     $availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction SilentlyContinue
        echo     if ($availableUpdates.Count -eq 0) {
        echo         Write-Log "No Windows Updates available" "INFO"
        echo     } else {
        echo         Write-Log "Found $($availableUpdates.Count) Windows Updates available" "INFO"
        echo         Write-Log "Installing Windows Updates (this may take some time)"
        echo         Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        echo         Write-Log "Windows Updates installed successfully" "SUCCESS"
        echo     }
        echo.
        echo     # Check for winget and upgrade applications
        echo     Write-Log "Checking for winget availability"
        echo     if (Get-Command winget -ErrorAction SilentlyContinue) {
        echo         Write-Log "Found winget, upgrading applications (timeout: 30 minutes)"
        echo         $timeout = 1800
        echo         $job = Start-Job -ScriptBlock { 
        echo             $result = winget upgrade --all --include-unknown --silent --accept-package-agreements --accept-source-agreements
        echo             return $result
        echo         }
        echo         $completed = Wait-Job -Job $job -Timeout $timeout
        echo         if ($completed -and $completed.State -eq 'Completed') {
        echo             $jobOutput = Receive-Job -Job $job
        echo             $jobOutput ^| Out-File -FilePath "$logDir\winget_output.log" -Append
        echo             Write-Log "winget upgrade completed successfully" "SUCCESS"
        echo             Write-Log "Details saved to $logDir\winget_output.log"
        echo         } else {
        echo             Write-Log "winget upgrade timed out or failed" "WARNING"
        echo             if ($job.State -eq 'Running') {
        echo                 Write-Log "Stopping hung winget job" "WARNING"
        echo                 Stop-Job -Job $job
        echo             }
        echo         }
        echo         Remove-Job -Job $job -Force
        echo     } else {
        echo         Write-Log "winget not found. Skipping application upgrades" "WARNING"
        echo         Write-Log "Consider installing the App Installer package from the Microsoft Store"
        echo     }
        echo ^} catch {
        echo     Write-Log "Error: $($_.Exception.Message)" "ERROR"
        echo     Write-Log "StackTrace: $($_.ScriptStackTrace)" "ERROR"
        echo     exit 1
        echo ^} finally {
        echo     Write-Log "Reverting execution policy to Default"
        echo     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Default -Force -ErrorAction SilentlyContinue
        echo     Write-Log "Stopping transcript"
        echo     Stop-Transcript
        echo     Write-Log "Checking reboot status"
        echo     try {
        echo         $rebootNeeded = Get-WURebootStatus -Silent
        echo         if ($rebootNeeded) {
        echo             Write-Log "Reboot required after updates" "WARNING"
        echo             $title = "System Restart Required"
        echo             $message = "Windows Updates require a system restart.`n`nRestart now?"
        echo             $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Restarts the computer now."
        echo             $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does not restart the computer."
        echo             $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        echo             $result = $host.UI.PromptForChoice($title, $message, $options, 0)
        echo             if ($result -eq 0) {
        echo                 Write-Log "User confirmed reboot. Restarting computer..."
        echo                 Restart-Computer -Force
        echo             } else {
        echo                 Write-Log "User declined reboot. Manual restart recommended."
        echo             }
        echo         } else {
        echo         Write-Log "No reboot needed" "SUCCESS"
        echo         }
        echo     } catch {
        echo         Write-Log "Failed to check reboot status: $($_.Exception.Message)" "ERROR"
        echo     }
        echo     Write-Log "Update process completed" "SUCCESS"
        echo ^}
    ) > "!PSScriptPath!"

    if errorlevel 1 (
        echo %DATE% %TIME% - [BATCH] Error: Failed to create PowerShell script >> "!LogFile!"
        echo Error: Could not create PowerShell script.
        pause
        exit /b 1
    ) else (
        echo %DATE% %TIME% - [BATCH] PowerShell script created successfully >> "!LogFile!"
    )

    :: Run PowerShell script with bypass
    echo %DATE% %TIME% - [BATCH] Executing PowerShell script >> "!LogFile!"
    echo Executing PowerShell update script...

    echo %DATE% %TIME% - [BATCH] Command: powershell -NoProfile -ExecutionPolicy Bypass -File "!PSScriptPath!" -LogPath "!PSLogFile!" >> "!LogFile!"
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& { $ErrorActionPreference = 'Continue'; try { & '!PSScriptPath!' -LogPath '!PSLogFile!'; if ($LASTEXITCODE) { exit $LASTEXITCODE } } catch { Write-Error $_; exit 1 } }" >> "!LogFile!" 2>&1
    set "PS_EXIT_CODE=%ERRORLEVEL%"

    :: Check PS execution status
    if %PS_EXIT_CODE% NEQ 0 (
        echo %DATE% %TIME% - [BATCH] Error: PowerShell script failed with exit code %PS_EXIT_CODE%. >> "!LogFile!"
        echo Error: PowerShell script execution failed with exit code %PS_EXIT_CODE%.
        echo Check logs for details:
        echo - Batch Log: !LogFile!
        echo - PowerShell Log: !PSLogFile!
        echo The PowerShell script has been preserved at: !PSScriptPath!
    ) else (
        echo %DATE% %TIME% - [BATCH] PowerShell script executed successfully >> "!LogFile!"
        echo Updates completed successfully.
        echo %DATE% %TIME% - [BATCH] Cleaning up temporary files >> "!LogFile!"
        del "!PSScriptPath!" 2>nul
        echo Log file locations:
        echo - Batch Log: !LogFile!
        echo - PowerShell Log: !PSLogFile!
    )

    echo %DATE% %TIME% - [BATCH] Batch script completed >> "!LogFile!"
    echo.
    echo Process complete. Press any key to exit.
    pause > nul
    endlocal