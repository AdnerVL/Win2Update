# Windows Update and Software Upgrade Script

[![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)

<!-- Disclaimer: This script and documentation were created with the assistance of AI (GitHub Copilot). Please review and test before use in production environments. -->

A robust Windows system update automation solution that combines PowerShell and batch scripting to manage Windows Updates and application upgrades through winget. This script is designed for system administrators and power users who want to automate their Windows update process with detailed logging and error handling.

## ⚠️ Security Notice

Before using this script, please be aware of these security considerations:

- Review all scripts before execution in your environment
- Implement proper file and folder permissions
- Configure logging to a secure location
- Verify script integrity before each run
- Monitor update sources and network traffic
- Consider implementing hash verification
- Use environment-specific paths

## 🚀 Features

- Automated Windows Updates using the `PSWindowsUpdate` module
- Bulk application upgrades via `winget`
- Automatic privilege elevation
- Comprehensive error handling and logging
- Safe execution with environment checks
- Automatic module installation and configuration
- Smart reboot handling with user interaction
- Cleanup of temporary files

## 📋 Prerequisites

- Windows 10/11
- PowerShell 5.1 or later
- Internet connection
- Administrator privileges
- Windows Package Manager (`winget`)
- PowerShell modules: `PSWindowsUpdate`, `powershell-yaml` (auto-installed if missing)
- Secure storage location for scripts and logs
- Properly configured file system permissions

## 🛠️ Installation

1. Clone this repository or download the files:

   ```powershell
   git clone https://github.com/AdnerVL/Win2Update.git
   ```

2. Create and configure a secure location for the scripts:

   ```powershell
   # Example: Create directory and set permissions
   $scriptPath = "$env:ProgramFiles\WindowsUpdate"
   New-Item -Path $scriptPath -ItemType Directory -Force
   ```

3. Copy the files to your secure location and configure:
   - Move the downloaded files to your chosen location
   - Set NTFS permissions according to your security policy
   - Update configuration in the scripts
   - Test in a non-production environment first


## 📦 Components

- `RemoteW2Update.ps1`: Main PowerShell script for remote, multi-host Windows and app updates. Handles queueing, error logging, and can retry unreachable hosts. Uses PsExec for all remote execution (no WinRM/PSRemoting required).
- `RemoteW2Update_Improved.ps1`: Improved version of the remote script with enhanced error handling, optional parallelism for multiple hosts, structured JSON logging, and configurability (including winget hash verification).
- `AdvancedRemoteUpdate.ps1`: Advanced remote update script with built-in YAML-based tracking (hosts_tracking.yaml) to skip hosts updated within a configurable period (default 5 days). Performs Windows Updates, winget upgrades, firmware/driver updates via MSUpdate, and optional auto-reboot. Uses PsExec for remote execution (no WinRM/PSRemoting required), includes queue management with 3-hour retry for failures/unreachable hosts, connectivity checks, structured JSON logging (.logs directory), and handles timeouts up to 15 minutes per host. Implements own YAML parser without external module dependency.
- `UpdateScriptv1.ps1`: Standalone PowerShell script for local Windows and app updates, with logging, admin check, and optional auto-reboot.
- `RunRemoteW2Update.bat`: Batch file to launch `RemoteW2Update.ps1` with correct PowerShell policy.
- `RunUpdateScript.bat`: Batch file for launching `UpdateScriptv1.ps1` with elevation and debug logging.
- `hosts.txt`: List of target hostnames/IPs for remote updates (used by `RemoteW2Update.ps1`).
- `hostQueue.txt`: Tracks hosts that failed or are queued for retry (auto-managed, ignored by git).
- `errorLog.txt`: Error log for remote update failures (auto-managed, ignored by git).
- `Logs/`: Contains update and console logs for local/remote scripts (e.g., via UpdateScriptv1.ps1 or RemoteW2Update.ps1).
- `.logs/`: Auto-created directory for structured JSON logs from AdvancedRemoteUpdate.ps1.
- `.gitignore`: Excludes `.exe`, `.txt`, log, and queue files from version control.
- `Use.txt`: Security and usage best practices.
- `README.md`: This documentation file.


## 🚦 Usage

### Local (Single Machine) Update
1. **Run as Administrator:**
   - Right-click `RunUpdateScript.bat` and select "Run as administrator"
   - Or run from PowerShell (Admin):
     ```powershell
     & ".\RunUpdateScript.bat"
     ```
2. **What it does:**
   - Checks for admin rights and elevates if needed
   - Runs `UpdateScriptv1.ps1` to update Windows and apps using winget
   - Handles logging and optional auto-reboot


### Remote (Multi-Host) Update
1. **Prepare `hosts.txt`:**
   - List all target hostnames or IPs, one per line
2. **Run as Administrator:**
   - Right-click `RunRemoteW2Update.bat` and select "Run as administrator"
   - Or run from PowerShell (Admin):
     ```powershell
     & ".\RunRemoteW2Update.bat"
     ```
3. **What it does:**
   - Reads `hosts.txt` for targets
   - Queues unreachable hosts in `hostQueue.txt` for retry (auto-managed)
   - Uses PsExec to run all update and upgrade steps on each remote host with full admin rights (no WinRM/PSRemoting required)
   - Logs errors to `errorLog.txt` and all update activity in `Logs/`

### Advanced Remote (Multi-Host) Update with Tracking
1. **Prepare `hosts.txt` or configuration:**
   - List all target hostnames or IPs, one per line in `hosts.txt`
   - Optional: Configure `hosts_tracking.yaml` for per-host settings (auto-created if missing)
2. **Run as Administrator:**
   - Right-click `RunAdvancedUpdate.bat` and select "Run as administrator"
   - Or run from PowerShell (Admin):
     ```powershell
     & ".\RunAdvancedUpdate.bat"
     ```
3. **Example Commands:**
   - Run with default settings (5-day skip, auto-reboot off, 3-hour retry):
     ```powershell
     .\AdvancedRemoteUpdate.ps1
     ```
   - Force retry all queued hosts and enable auto-reboot:
     ```powershell
     .\AdvancedRemoteUpdate.ps1 -ForceRetry -AutoReboot -Debug
     ```
   - Skip queue completely and change skip days to 7:
     ```powershell
     .\AdvancedRemoteUpdate.ps1 -SkipQueue -SkipDays 7
     ```
   - Specify custom files and retry after 30 minutes:
     ```powershell
     .\AdvancedRemoteUpdate.ps1 -QueueDuration 1800 -HostsFile "myhosts.txt" -YamlFile "custom.yaml"
     ```
4. **What it does:**
   - Tracks update status in a YAML file (.logs directory for structured logs) to skip hosts updated within configurable days (default 5)
   - Performs Windows Updates (including firmware/drivers via MSUpdate), winget upgrades, and optional auto-reboot
   - Queues unreachable/failed hosts for retry (default 3 hours, configurable)
   - Uses JSON-structured logging for successes and errors (no external YAML module required; built-in parser)

### Logging and Error Handling
- Log files are created in the `Logs` directory for each run
- Remote errors are logged in `errorLog.txt`
- Hosts that fail or are unreachable are queued in `hostQueue.txt` for later retry
- All `.txt` and `.exe` files, logs, and queue files are excluded from git by `.gitignore`


## 🛠 Logging and Troubleshooting

- **Log Files:**
  - Logs are stored in the `Logs` directory.
  - Example log files:
    - `UpdateLog_<timestamp>.txt`
    - `UpdateLog_<timestamp>.txt.winget`
    - `UpdateLog_Console_<timestamp>.txt`
  - Remote error log: `errorLog.txt`
  - Host queue for retry: `hostQueue.txt`
  - No WinRM/PSRemoting configuration is required or performed

- **Troubleshooting:**
  - Check log files for errors and warnings.
  - Ensure proper permissions on the `Logs` directory.
  - Verify internet connectivity for updates.
  - Use `-Verbose` flag for detailed output.
  - For remote updates, check `errorLog.txt` and `hostQueue.txt` for issues and retry status.

## ⚙️ Configuration

The script automatically configures:

- PowerShell execution policy (temporarily)
- Windows Update service
- Package providers (NuGet)
- Required PowerShell modules

## 📅 Update History

- **October 2, 2025:** Analyzed RunAdvancedUpdate.bat and AdvancedRemoteUpdate.ps1, updated documentation with detailed usage examples, expanded component descriptions, security enhancements from Use.txt integration, and log directory clarifications.
- **October 1, 2025:** Added AdvancedRemoteUpdate.ps1 script and updated documentation.
- **June 9, 2025:** Added logging and troubleshooting section.
- **May 23, 2025:** Initial release.

## ⚠️ Important Security Notes

- Always backup important data before running system updates
- Use approved network connections only
- Implement script signing for production use
- Monitor update processes for anomalies
- Review logs for security events
- Use HTTPS for any network operations
- Keep scripts in access-controlled locations
- Implement audit logging where possible
- Consider using PAM solutions for privileged operations
- Corporate environments should implement additional security controls

### Access Controls
1. Script directory: Admins (Full), System (Full)
2. Log directory: Service Account (Write), Admins (Full)
3. Temp directory: Service Account (Full), cleaned after execution

### Performance & Security
- Implement log rotation
- Monitor disk space
- Clean temporary files
- Review access logs
- Validate update sources
- Ensure PsExec is available and allowed by endpoint security
- Use approved proxy settings where applicable

**See Use.txt for detailed security and usage best practices, including NTFS permissions, PAM integration, approved paths, and corporate environment guidance.**

## 📄 License

This project is provided as-is, without warranty. Use at your own risk.

## 🤝 Contributing

Contributions are welcome! Please follow security guidelines when submitting PRs.

---
Last updated: October 2, 2025
