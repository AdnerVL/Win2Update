# Windows Update and Software Upgrade Script

<!-- Disclaimer: This script and documentation were created with the assistance of AI (GitHub Copilot and Grock). Please review and test before use in production environments. -->

This project provides a comprehensive batch and PowerShell-based solution for updating Windows and upgrading installed applications on a Windows system. It is designed to automate the process of keeping your system and software up to date, with detailed logging and optional reboot handling.

## Features

- Updates Windows using the `PSWindowsUpdate` PowerShell module
- Upgrades all installed applications using `winget`
- Handles required reboots interactively
- Creates detailed logs for both batch and PowerShell operations
- Checks for administrator privileges and internet connectivity

## Files

- `RunUpdateScript.bat`: Main batch script to orchestrate the update process. It generates and runs a PowerShell script, manages logs, and handles errors and cleanup.
- `UpdateScriptv1.ps1`: (Optional/legacy) Example or previous version of the PowerShell update script.
- `Use.txt`: (Optional) May contain usage notes or additional information.

## Usage

1. **Run as Administrator:**
   - Right-click `RunUpdateScript.bat` and select **Run as administrator**.
2. **Follow Prompts:**
   - The script will check for required permissions, internet connectivity, and then proceed to update Windows and installed applications.
   - If a reboot is required, you will be prompted to reboot or skip.
3. **Logs:**
   - Logs are saved in `C:\Tools\Logs` or your `%TEMP%` directory if the default is unavailable.
   - Log file names include timestamps for easy tracking.

## Requirements

- Windows 10/11
- PowerShell (included by default on modern Windows)
- Internet access for updates
- `winget` (Windows Package Manager) for application upgrades

## Notes

- The script will attempt to elevate privileges if not run as administrator.
- If `winget` is not found, application upgrades will be skipped.
- All actions and errors are logged for troubleshooting.

## License

This project is provided as-is, without warranty. Use at your own risk.
