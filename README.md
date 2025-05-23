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

- `RunUpdateScript.bat`: Main entry point that manages the update process
- `UpdateScriptv1.ps1`: Core PowerShell update implementation
- `Use.txt`: Additional usage notes and troubleshooting
- `README.md`: This documentation file

## 🚦 Usage

1. **Run as Administrator:**
   - Right-click `RunUpdateScript.bat`
   - Select "Run as administrator"
   - Or run from PowerShell (Admin):
   
     ```powershell
     & ".\RunUpdateScript.bat"
     ```

2. **Process Overview:**
   - Validates script integrity
   - Checks for admin rights
   - Verifies internet connectivity through approved channels
   - Installs/updates required PowerShell modules
   - Runs Windows Update
   - Upgrades installed applications
   - Handles reboots if needed

3. **Logging:**
   - Log files are created in a configurable secure location
   - Log files use timestamp format: `UpdateLog_YYYYMMDD_HHMMSS.txt`
   - Secure log rotation implemented
   - Default permissions restrict access to administrators and system

## ⚙️ Configuration

The script automatically configures:

- PowerShell execution policy (temporarily)
- Windows Update service
- Package providers (NuGet)
- Required PowerShell modules

## 🔍 Troubleshooting

- Check logs in your configured log directory
- Ensure PowerShell is not restricted (`Get-ExecutionPolicy`)
- Verify internet connectivity through approved channels
- Check Windows Update service is running
- Ensure `winget` is installed for app upgrades
- Verify file permissions and access rights

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

## 📄 License

This project is provided as-is, without warranty. Use at your own risk.

## 🤝 Contributing

Contributions are welcome! Please follow security guidelines when submitting PRs.

---
Last updated: May 23, 2025
