@echo off
setlocal EnableDelayedExpansion

:: Debug: Log start of script
echo [DEBUG] Starting batch script at %date% %time% > "%TEMP%\UpdateScriptDebug.txt"
echo [DEBUG] Current directory: %CD% >> "%TEMP%\UpdateScriptDebug.txt"
echo [DEBUG] Script path: %~f0 >> "%TEMP%\UpdateScriptDebug.txt"

:: Set paths early
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=!SCRIPT_DIR:~0,-1!"
echo [DEBUG] SCRIPT_DIR set to: !SCRIPT_DIR! >> "%TEMP%\UpdateScriptDebug.txt"

:: Verify script exists
if not exist "%~f0" (
    echo [ERROR] Script file not found: %~f0 >> "%TEMP%\UpdateScriptDebug.txt"
    exit /b 1
)
echo [DEBUG] Script file verified: %~f0 >> "%TEMP%\UpdateScriptDebug.txt"

:: Check for admin rights
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    :: Debug: Log elevation attempt
    echo [DEBUG] Not elevated, requesting elevation >> "%TEMP%\UpdateScriptDebug.txt"
    :: Create VBScript for elevation
    set "VBS_FILE=%TEMP%\Elevate_%RANDOM%.vbs"
    echo [DEBUG] Creating VBScript: !VBS_FILE! >> "%TEMP%\UpdateScriptDebug.txt"
    (echo Set UAC = CreateObject^("Shell.Application"^)
     echo UAC.ShellExecute "%~f0", "", "%CD%", "runas", 1) > "!VBS_FILE!" || (
        echo [ERROR] Failed to create VBScript: !VBS_FILE! >> "%TEMP%\UpdateScriptDebug.txt"
        exit /b 1
    )
    :: Debug: Log VBScript contents
    echo [DEBUG] VBScript contents: >> "%TEMP%\UpdateScriptDebug.txt"
    type "!VBS_FILE!" >> "%TEMP%\UpdateScriptDebug.txt" 2>nul
    :: Run VBScript and capture output
    cscript //nologo "!VBS_FILE!" > "%TEMP%\VBSOutput.txt" 2>&1
    set "EXIT_CODE=%ERRORLEVEL%"
    :: Log VBScript output
    echo [DEBUG] VBScript output: >> "%TEMP%\UpdateScriptDebug.txt"
    type "%TEMP%\VBSOutput.txt" >> "%TEMP%\UpdateScriptDebug.txt" 2>nul
    :: Clean up VBScript and output
    del "!VBS_FILE!" 2>nul
    del "%TEMP%\VBSOutput.txt" 2>nul
    echo [DEBUG] Elevation attempt completed with exit code !EXIT_CODE! >> "%TEMP%\UpdateScriptDebug.txt"
    :: Fallback log if elevation fails
    if !EXIT_CODE! NEQ 0 (
        echo [ERROR] Elevation failed with exit code !EXIT_CODE! >> "%TEMP%\UpdateScriptDebug.txt"
        for /f "delims=" %%a in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd_HHmmss')"') do set "TIMESTAMP=%%a"
        echo [ERROR] Elevation failed. Check %TEMP%\UpdateScriptDebug.txt for details > "!SCRIPT_DIR!\Logs\ElevationFailure_!TIMESTAMP!.txt" 2>nul
        exit /b !EXIT_CODE!
    )
    exit /b !EXIT_CODE!
)

:: Debug: Log elevated state
echo [DEBUG] Running with admin rights at %date% %time% >> "%TEMP%\UpdateScriptDebug.txt"

cd /d "!SCRIPT_DIR!" || (
    echo [ERROR] Failed to set working directory: !SCRIPT_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
    exit /b 1
)
echo [DEBUG] Working directory set to: !SCRIPT_DIR! >> "%TEMP%\UpdateScriptDebug.txt"

set "LOG_DIR=!SCRIPT_DIR!\Logs"
set "TEMP_DIR=!SCRIPT_DIR!\Temp"

:: Validate TEMP_DIR
if "!TEMP_DIR!"=="!SCRIPT_DIR!" (
    echo [ERROR] TEMP_DIR matches SCRIPT_DIR, resetting to safe path >> "%TEMP%\UpdateScriptDebug.txt"
    set "TEMP_DIR=%TEMP%\Win2UpdateTemp"
)

for /f "delims=" %%a in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd_HHmmss')"') do set "TIMESTAMP=%%a"
set "LOG_FILE=!LOG_DIR!\UpdateLog_!TIMESTAMP!.txt"
set "CONSOLE_LOG=!LOG_DIR!\UpdateLog_Console_!TIMESTAMP!.txt"

:: Create directories with error handling
if not exist "!LOG_DIR!" (
    mkdir "!LOG_DIR!" || (
        echo [ERROR] Failed to create log directory: !LOG_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
        exit /b 1
    )
    echo [DEBUG] Created log directory: !LOG_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
)

if not exist "!TEMP_DIR!" (
    mkdir "!TEMP_DIR!" || (
        echo [ERROR] Failed to create temp directory: !TEMP_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
        exit /b 1
    )
    echo [DEBUG] Created temp directory: !TEMP_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
)

:: Test log file access
echo [DEBUG] Testing log file access: !LOG_FILE! >> "%TEMP%\UpdateScriptDebug.txt"
(echo Test > "!LOG_FILE!" && del "!LOG_FILE!") || (
    echo [ERROR] Cannot write to log file: !LOG_FILE! >> "%TEMP%\UpdateScriptDebug.txt"
    exit /b 1
)
echo [DEBUG] Log file access test passed >> "%TEMP%\UpdateScriptDebug.txt"

:: Run PowerShell script
echo [DEBUG] Running PowerShell script: !SCRIPT_DIR!\UpdateScriptv1.ps1 >> "%TEMP%\UpdateScriptDebug.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCRIPT_DIR!\UpdateScriptv1.ps1" -LogPath "!LOG_FILE!" -AutoReboot > "!CONSOLE_LOG!" 2>&1
set "EXIT_CODE=!ERRORLEVEL!"
echo [DEBUG] PowerShell script completed with exit code !EXIT_CODE! >> "%TEMP%\UpdateScriptDebug.txt"

:: Clean up old logs
for /f "skip=5 delims=" %%F in ('dir /b /o-d "!LOG_DIR!\*.txt" 2^>nul') do (
    del "!LOG_DIR!\%%F" 2>nul
    echo [DEBUG] Deleted old log: %%F >> "%TEMP%\UpdateScriptDebug.txt"
)

:: Clean up temp directory with protection
if exist "!TEMP_DIR!" (
    if "!TEMP_DIR!"=="!SCRIPT_DIR!" (
        echo [ERROR] TEMP_DIR matches SCRIPT_DIR, skipping cleanup to prevent self-deletion >> "%TEMP%\UpdateScriptDebug.txt"
    ) else (
        rd /s /q "!TEMP_DIR!" 2>nul
        if exist "!TEMP_DIR!" (
            echo [ERROR] Failed to clean up temp directory: !TEMP_DIR! >> "%TEMP%\UpdateScriptDebug.txt"
        ) else (
            echo [DEBUG] Cleaned up temp directory >> "%TEMP%\UpdateScriptDebug.txt"
        )
    )
)

exit /b !EXIT_CODE!