# Windows Update and Software Upgrade Script

[![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)

<!-- Disclaimer: This script and documentation were created with the assistance of AI (GitHub Copilot). Please review and test before use in production environments. -->

A robust Windows system update automation solution that combines PowerShell and batch scripting to manage Windows Updates and application upgrades through winget. This script is designed for system administrators and power users who want to automate their Windows update process with detailed logging and error handling.

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

## 🛠️ Installation

1. Clone this repository or download the files:
   ```powershell
   git clone https://github.com/yourusername/Win2Update.git
   ```
2. Place the files in a permanent location (e.g., `C:\Tools\Git\Win2Update`)

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
     & "C:\Tools\Git\Win2Update\RunUpdateScript.bat"
     ```

2. **Process Overview:**
   - Checks for admin rights
   - Verifies internet connectivity
   - Installs/updates required PowerShell modules
   - Runs Windows Update
   - Upgrades installed applications
   - Handles reboots if needed

3. **Logging:**
   - Batch log: `C:\Tools\Logs\UpdateAllLog_[DateTime].txt`
   - PowerShell log: `C:\Tools\Logs\PSUpdateLog_[DateTime].txt`

## ⚙️ Configuration

The script automatically configures:
- PowerShell execution policy (temporarily)
- Windows Update service
- Package providers (NuGet)
- Required PowerShell modules

## 🔍 Troubleshooting

- Check logs in `C:\Tools\Logs\` for detailed error information
- Ensure PowerShell is not restricted (`Get-ExecutionPolicy`)
- Verify internet connectivity
- Check Windows Update service is running
- Ensure `winget` is installed for app upgrades

## ⚠️ Important Notes

- Always backup important data before running system updates
- The script requires internet access for downloads
- Some updates may require multiple reboots
- Execution time varies based on available updates
- Corporate environments may require additional configuration

## 📄 License

This project is provided as-is, without warranty. Use at your own risk.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---
Last updated: May 23, 2025
