# Windows Remote Update Script

A PowerShell script for automating Windows Updates on multiple remote computers using PsExec.

## Requirements

- Windows with PowerShell 7.0 or higher
- Administrator privileges
- PsExec.exe or PsExec64.exe
- SMB access to target machines (port 445)
- Target machines must be pingable
- .NET COM objects support for Windows Update API

## 📋 Prerequisites

- Windows operating system
- PowerShell 7.0 or later
- Administrator privileges (required to run script)
- PsExec.exe or PsExec64.exe in the script directory
- SMB access to target machines (port 445)
- Target machines must be accessible via ping
- Remote machines must have Windows Update service available

## � Required Files

- `AdvancedRemoteUpdate.ps1`: Main script
- `PsExec.exe` or `PsExec64.exe`: Required for remote execution
- `hosts.txt`: List of target computers (one hostname per line)
- `hosts_tracking.yaml`: Tracks update history (auto-created if missing)
- `hostQueue.txt`: Manages retry queue (auto-created if missing)

## ⚙️ Script Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| HostsFile | string | hosts.txt | Path to file containing target hostnames (one per line) |
| YamlFile | string | hosts_tracking.yaml | Path to YAML tracking file for update history |
| QueueFile | string | hostQueue.txt | Path to queue management file for failed hosts |
| SkipDays | int | 5 | Skip hosts successfully updated within this many days (0-365) |
| ThrottleLimit | int | 10 | Maximum parallel hosts to process simultaneously (1-50) |
| QueueDuration | int | 3600 | Retry wait time in seconds for queued hosts (default: 1 hour, 0-86400) |

## � Usage Examples

### Basic Usage

```powershell
.\AdvancedRemoteUpdate.ps1
```

### With Custom Parameters

```powershell
.\AdvancedRemoteUpdate.ps1 -HostsFile "custom_hosts.txt" -SkipDays 7 -AutoReboot
```

### With Custom Throttle Limit

```powershell
.\AdvancedRemoteUpdate.ps1 -ThrottleLimit 5 # Process 5 hosts in parallel
```

### With Custom Queue Duration

```powershell
.\AdvancedRemoteUpdate.ps1 -QueueDuration 7200 # 2 hours retry wait
```

### Combining Multiple Parameters

```powershell
.\AdvancedRemoteUpdate.ps1 -SkipDays 7 -ThrottleLimit 15 -QueueDuration 1800
```

## � Tracking and Logging

### YAML Tracking
The script maintains a YAML file (`hosts_tracking.yaml`) with the following information for each host:
- Last connection timestamp
- Last successful update timestamp
- Update success status

Example:

```yaml
systems:
- hostname: SERVER01
  last_connection_timestamp: 2025-10-03T10:00:00Z
  last_successful_update_timestamp: 2025-10-03T10:30:00Z
  update_success: true
```

### Logging
- Detailed logs are stored in `.logs/update_script.log`
- Includes timestamps, log levels, and host-specific information
- Color-coded console output for better visibility

## 🔄 Queue Management

The script implements a sophisticated queue management system:

- Failed or unreachable hosts are automatically added to retry queue
- Default retry window is 1 hour (configurable via `QueueDuration`)
- Queue status is displayed in execution summary with retry times
- Queue file (`hostQueue.txt`) persists between runs
- Hosts remain in queue until retry duration expires
- Queue entries are automatically cleaned when expired


## ✅ Execution Summary

After each run, the script displays a comprehensive summary:

```
========================================
EXECUTION SUMMARY
========================================
Total Hosts:    50
Successful:     45         (Green)
Skipped:        3          (Yellow)
Failed:         2          (Red)
Errors:         0          (Red)
Queued:         2          (Yellow)

Hosts in retry queue:
  SERVER-FAIL-01 - retry in 45 minutes
  SERVER-FAIL-02 - retry in 45 minutes
```

**Status Explanations:**
- **Successful**: Update completed successfully
- **Skipped-Queue**: Host in retry queue, skipped this run
- **Skipped-RecentUpdate**: Host updated within SkipDays threshold
- **Failed**: Update attempt failed, added to queue
- **Error**: Processing error occurred
- Failed updates count
- Unreachable hosts count
- Current queue status with retry times

## 🛡️ Security Considerations

1. Must run as Administrator

2. Target machines must have:
   - Network connectivity (ping)
   - SMB (port 445) accessible
   - Remote administrative access

3. File security:
   - PsExec.exe/PsExec64.exe in script directory
   - Proper file permissions
   - Secure log storage

4. Network security:
   - Use in trusted networks only
   - Monitor remote connections
   - Review execution logs

## ⚠️ Important Notes

1. Script Behavior:
   - 10-minute timeout per host update
   - Automatic directory creation (`.logs` folder)
   - Built-in YAML handling (no external modules needed)
   - Thread-safe parallel processing with mutex locks

2. Error Handling:
   - Failed hosts are queued for retry
   - Detailed error logging to `.logs/update_script.log`
   - Color-coded console output for visibility
   - Comprehensive exception handling

3. Performance:
   - Parallel host processing (configurable throttle limit)
   - Configurable retry intervals
   - Smart update skipping based on history
   - Pre-filtering for connectivity and recent updates

## 🔧 Best Practices

1. Host Management:
   - Keep `hosts.txt` updated with valid hostnames
   - Remove unreachable or decommissioned hosts
   - Review queue periodically for persistent failures
   - Test connectivity before running on all hosts

2. Maintenance:
   - Monitor `.logs/update_script.log` for growth
   - Backup `hosts_tracking.yaml` periodically
   - Archive old logs to prevent disk space issues
   - Keep hosts.txt and tracking files synchronized

3. Deployment:
   - Test in small groups first (use SkipDays to prevent repeated runs)
   - Start with default ThrottleLimit and adjust based on network capacity
   - Monitor initial runs to understand queue dynamics
   - Schedule runs during maintenance windows

4. Queue Management:
   - Review queued hosts in execution summary
   - Investigate persistent failures
   - Adjust QueueDuration if needed (e.g., increase for WAN connections)
   - Clear queue file if needed: `@{} | Out-File hostQueue.txt`

## 📚 Troubleshooting

### Common Issues and Solutions:

1. **Connection Failures:**
   - Verify network connectivity: `ping <hostname>`
   - Check SMB port 445: `Test-NetConnection -ComputerName <hostname> -Port 445`
   - Validate target hostname spelling
   - Check firewall rules on target machine
   - Verify you have network access to target subnet

2. **Update Failures:**
   - Check Windows Update service: `Get-Service -Name wuauserv`
   - Review error logs in `.logs/update_script.log`
   - Verify administrative access to target machine
   - Check target machine disk space
   - Ensure Windows Update service is running

3. **Queue Issues:**
   - Clear queue file: `Clear-Content hostQueue.txt` or delete and recreate
   - Adjust retry duration: increase QueueDuration for WAN/slow networks
   - Monitor queue growth: check `hostQueue.txt` for persistence
   - Review persistent failures in hosts_tracking.yaml

4. **PowerShell Version:**
   - Verify you're running PS 7.0+: `$PSVersionTable.PSVersion`
   - Script requires PowerShell 7.0 or higher
   - Not compatible with Windows PowerShell (5.1)

5. **PsExec Issues:**
   - Ensure `PsExec.exe` or `PsExec64.exe` is in script directory
   - Run script as Administrator
   - Check that PsExec hasn't been quarantined by antivirus
   - EULA acceptance is automatic with `-accepteula` flag

6. **Permission Errors:**
   - Run script with `Run as Administrator`
   - Verify target machine admin credentials/access
   - Check SMB share permissions
   - Verify local admin rights on target machine


## 🛠️ Implementation Details

### Update Process on Remote Host:
1. Windows Update service validation
2. Update session creation via COM objects
3. Search for available updates
4. Download and installation
5. Group Policy update (`gpupdate /force`)
6. WinGet installation (if not present)
7. WinGet package upgrade
8. Status tracking and reporting

### Error Handling:
- Connection timeouts (10-minute limit per host)
- SMB port 445 connectivity checks
- Windows Update service availability
- Update discovery and download failures
- Installation errors
- Network connection issues

### Parallel Processing:
- Thread-safe logging with mutex locks
- Configurable throttle limit (1-50 hosts)
- Proper variable scoping using `$using:`
- Host-specific error isolation
- Automatic queue management for failures

### Logging System:
- Structured timestamp format (ISO 8601 UTC)
- Color-coded console output (Green=Success, Red=Error, Yellow=Warning)
- Centralized log file in `.logs/update_script.log`
- Thread-safe file writes
- Both console and file logging

## 🤖 Automatic Features

1. Environment Setup:
   - Log directory creation (`.logs`)
   - YAML file initialization (if missing)
   - Queue file initialization (if missing)
   - PsExec executable detection
   - PowerShell version validation (7.0+)

2. Host Management:
   - Connection verification via ping
   - Update history tracking
   - Automatic queue management
   - Status monitoring and reporting
   - Sequential pre-filtering for connectivity

3. Update Process:
   - Service validation on remote machine
   - Update discovery via COM objects
   - Download management
   - Installation tracking
   - WinGet installation and upgrade
   - Group Policy refresh
   - Automatic reboot detection

4. Queue Management:
   - Automatic addition of failed hosts
   - Timestamp-based retry management
   - Automatic cleanup of expired entries
   - Persistence across script runs

## 📄 License

This project is provided as-is, without warranty. Use at your own risk.

## 🔄 Contributing

Contributions are welcome! Please follow security best practices when submitting changes.

---
Last updated: November 13, 2025
