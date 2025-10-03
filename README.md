# Windows Remote Update Script

A PowerShell script for automating Windows Updates on multiple remote computers using PsExec.

## Requirements

- Windows with PowerShell 5.1+
- Administrator privileges
- PsExec.exe/PsExec64.exe
- SMB access to target machines (port 445)
- Target machines must be pingable

## 📋 Prerequisites

- Windows operating system
- PowerShell 5.1 or later
- Administrator privileges
- PsExec.exe or PsExec64.exe in the script directory
- SMB access to target machines (port 445)
- Target machines must be accessible via ping

## � Required Files

- `AdvancedRemoteUpdate.ps1`: Main script
- `PsExec.exe` or `PsExec64.exe`: Required for remote execution
- `hosts.txt`: List of target computers (one hostname per line)
- `hosts_tracking.yaml`: Tracks update history (auto-created if missing)
- `hostQueue.txt`: Manages retry queue (auto-created if missing)

## ⚙️ Script Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| HostsFile | string | hosts.txt | Path to file containing target hostnames |
| YamlFile | string | hosts_tracking.yaml | Path to YAML tracking file |
| QueueFile | string | hostQueue.txt | Path to queue management file |
| SkipDays | int | 5 | Skip hosts updated within this many days |
| AutoReboot | switch | false | Allow automatic reboots after updates |
| QueueDuration | int | 10800 | Retry wait time in seconds (default: 3 hours) |

## � Usage Examples

### Basic Usage

```powershell
.\AdvancedRemoteUpdate.ps1
```

### With Custom Parameters

```powershell
.\AdvancedRemoteUpdate.ps1 -HostsFile "custom_hosts.txt" -SkipDays 7 -AutoReboot
```

### With Custom Queue Duration

```powershell
.\AdvancedRemoteUpdate.ps1 -QueueDuration 7200 # 2 hours retry wait
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

- Failed or unreachable hosts are added to the queue
- Default retry window is 3 hours (configurable)
- Queue status displayed in execution summary
- Queue file (`hostQueue.txt`) persists between runs


## � Execution Summary

The script provides a comprehensive summary after completion:

- Total number of hosts processed
- Successful updates count
- Skipped hosts count
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
   - 15-minute timeout per host
   - Automatic directory creation
   - Built-in YAML handling (no external module needed)

2. Error Handling:
   - Failed hosts are queued for retry
   - Detailed error logging
   - Color-coded console output

3. Performance:
   - Sequential host processing
   - Configurable retry intervals
   - Smart update skipping based on history

## 🔧 Best Practices

1. Host Management:
   - Keep hosts.txt updated
   - Remove unreachable hosts
   - Review queue periodically

2. Maintenance:
   - Monitor log growth
   - Clean old log files
   - Backup tracking files

3. Deployment:
   - Test in small groups first
   - Use reasonable skip days
   - Monitor initial runs

## 📚 Troubleshooting

Common issues and solutions:

1. Connection Failures:
   - Verify network connectivity
   - Check SMB port 445
   - Validate target hostname

2. Update Failures:
   - Check target Windows Update service
   - Review error logs
   - Verify admin access

3. Queue Issues:
   - Clear queue file if needed
   - Adjust retry duration
   - Monitor queue growth


## 🛠️ Implementation Details

1. Update Process:
   - Windows Update service check
   - Update discovery and filtering
   - Download and installation
   - Status tracking and reporting

2. Error Handling:
   - Connection timeouts
   - Update failures
   - Service issues
   - Network problems

3. Logging System:
   - Structured JSON format
   - Color-coded console output
   - Timestamped entries
   - Host-specific tracking

## 🤖 Automatic Features

1. Environment Setup:
   - Log directory creation
   - YAML file initialization
   - Queue management
   - PsExec detection

2. Host Management:
   - Connection verification
   - Update history tracking
   - Queue handling
   - Status monitoring

3. Update Process:
   - Service validation
   - Update discovery
   - Download management
   - Installation tracking

## 📄 License

This project is provided as-is, without warranty. Use at your own risk.

## 🔄 Contributing

Contributions are welcome! Please follow security best practices when submitting changes.

---
Last updated: October 3, 2025
