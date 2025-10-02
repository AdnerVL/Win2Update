@echo off
setlocal EnableDelayedExpansion

REM Set default values for parameters
set "SKIP_QUEUE=false"
set "FORCE_RETRY=false"
set "DEBUG=true"
set "AUTO_REBOOT=false"

REM Process command line arguments
:arg_loop
if not "%1"=="" (
    if /i "%1"=="-skipqueue" set "SKIP_QUEUE=true"
    if /i "%1"=="-forcetry" set "FORCE_RETRY=true"
    if /i "%1"=="-debug" set "DEBUG=true"
    if /i "%1"=="-autoreboot" set "AUTO_REBOOT=true"
    shift
    goto :arg_loop
)

REM Set script directory path
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM Create logs directory if it doesn't exist
if not exist "!SCRIPT_DIR!\.logs" mkdir "!SCRIPT_DIR!\.logs"

REM Set the log file path
set "LOG_FILE=!SCRIPT_DIR!\.logs\update_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log"
set "LOG_FILE=!LOG_FILE: =0!"

echo =========================================
echo Windows Update Process Starting
echo =========================================
echo Script Directory: !SCRIPT_DIR!
echo Log File: !LOG_FILE!
echo Skip Queue: !SKIP_QUEUE!
echo Force Retry: !FORCE_RETRY!
echo Debug Mode: !DEBUG!
echo =========================================

REM Run PowerShell script with elevation and logging
echo Building PowerShell command...

REM Create a temporary script for the elevated process
set "TEMP_SCRIPT=!SCRIPT_DIR!\.logs\temp_elevate.ps1"

echo $ErrorActionPreference = 'Stop' > "!TEMP_SCRIPT!"
echo $VerbosePreference = 'Continue' >> "!TEMP_SCRIPT!"
echo $DebugPreference = 'Continue' >> "!TEMP_SCRIPT!"
echo $scriptPath = Join-Path '!SCRIPT_DIR!' 'AdvancedRemoteUpdate.ps1' >> "!TEMP_SCRIPT!"
echo Write-Host "[Elevated] Starting Windows Update process from $scriptPath" >> "!TEMP_SCRIPT!"
echo if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Main script not found: $scriptPath" } >> "!TEMP_SCRIPT!"

echo $scriptParams = @{ >> "!TEMP_SCRIPT!"
echo     'HostsFile' = Join-Path '!SCRIPT_DIR!' 'hosts.txt' >> "!TEMP_SCRIPT!"
echo } >> "!TEMP_SCRIPT!"

if "!AUTO_REBOOT!"=="true" (
    echo $scriptParams['AutoReboot'] = $true >> "!TEMP_SCRIPT!"
)
if "!DEBUG!"=="true" (
    echo $scriptParams['Debug'] = $true >> "!TEMP_SCRIPT!"
)
if "!SKIP_QUEUE!"=="true" (
    echo $scriptParams['SkipQueue'] = $true >> "!TEMP_SCRIPT!"
)
if "!FORCE_RETRY!"=="true" (
    echo $scriptParams['ForceRetry'] = $true >> "!TEMP_SCRIPT!"
)

echo Write-Host "[Elevated] Starting script execution..." >> "!TEMP_SCRIPT!"
echo Start-Transcript -Path '!LOG_FILE!' -Force >> "!TEMP_SCRIPT!"
echo try { >> "!TEMP_SCRIPT!"
echo     ^& $scriptPath @scriptParams >> "!TEMP_SCRIPT!"
echo     if ($LASTEXITCODE -ne 0) { throw "Script failed with exit code $LASTEXITCODE" } >> "!TEMP_SCRIPT!"
echo     Write-Host "[Elevated] Script completed successfully" >> "!TEMP_SCRIPT!"
echo } catch { >> "!TEMP_SCRIPT!"
echo     Write-Error $_.Exception.Message >> "!TEMP_SCRIPT!"
echo     Write-Host "[Elevated] Full error details:" >> "!TEMP_SCRIPT!"
echo     $_ ^| Format-List * -Force >> "!TEMP_SCRIPT!"
echo     exit 1 >> "!TEMP_SCRIPT!"
echo } finally { >> "!TEMP_SCRIPT!"
echo     Stop-Transcript >> "!TEMP_SCRIPT!"
echo } >> "!TEMP_SCRIPT!"

echo Created temporary elevation script: !TEMP_SCRIPT!
echo =========================================

REM Execute the temporary script with elevation
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$result = Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"!TEMP_SCRIPT!\"' -Verb RunAs -PassThru -Wait; exit $result.ExitCode"

set EXIT_CODE=!ERRORLEVEL!

REM Display the log file contents
echo.
echo Log file contents:
echo =========================================
type "!LOG_FILE!"
echo =========================================

REM Clean up
del "!TEMP_SCRIPT!"

if !EXIT_CODE! NEQ 0 (
    echo Error: Script failed with exit code !EXIT_CODE!
    exit /b !EXIT_CODE!
)

if !ERRORLEVEL! NEQ 0 (
    echo Error occurred. Check the log file: !LOG_FILE!
    type "!LOG_FILE!"
) else (
    echo Update process completed. Check the log file for details: !LOG_FILE!
    type "!LOG_FILE!"
)

pause
endlocal