@echo off
setlocal
set SCRIPT_DIR=%~dp0

REM Run the RemoteW2Update.ps1 script with unrestricted policy
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%RemoteW2Update.ps1"

endlocal
