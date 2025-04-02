# Dynamic Threat Response System

## Overview

The Dynamic Threat Response System is a comprehensive security monitoring tool designed to detect and respond to potential threats on a computer system. It monitors network connections, running processes, and file activities to identify suspicious behaviors using predefined threat signatures. The system provides real-time visualization of threat levels and detailed logging of security events.

## Features

- **Real-time monitoring** of network connections and running processes
- **Threat detection** based on customizable signatures
- **Dynamic threat scoring** with visual representation
- **Comprehensive logging** of all security events and threats
- **User-friendly interface** with status indicators and controls
- **Customizable threat signatures** through the configuration interface
- **System resource monitoring** (CPU, memory, disk usage)

## Components

### 1. Main System (`main.py`)

The `DynamicThreatResponseSystem` class serves as the core controller, orchestrating all monitoring activities and connecting the different components. It:

- Initializes the monitoring system
- Manages the monitoring thread
- Updates system status based on threat detection
- Coordinates between the threat detector, logger, and UI

### 2. Threat Detection (`threat_detector.py`)

The `ThreatDetector` class handles the analysis of potential threats:

- Evaluates network connections against known malicious IPs and suspicious ports
- Examines running processes against known malicious process patterns
- Analyzes files for suspicious extensions and malware signatures
- Maintains and updates a threat score
- Implements thread-safe operations with locks

Key functionalities:
- IP validation and resolution
- Blacklist checking against IP ranges and specific addresses
- Process name pattern matching
- File content signature matching

### 3. Threat Signatures (`threat_signatures.py`)

The `ThreatSignatures` class manages the definitions of what constitutes a threat:

- Loads signature configurations from a JSON file
- Provides default signatures when configuration is not available
- Offers methods to access specific signature categories:
  - Network threats (suspicious ports, blacklisted IPs)
  - Process threats (risky processes, suspicious patterns)
  - File threats (suspicious extensions, malware signatures)
  - Network patterns (suspicious domains, TOR exit nodes)

### 4. Logging System (`logger.py`)

The `ThreatLogger` class handles all event and threat logging:

- Maintains a general event log and a dedicated threat log
- Supports different logging levels (info, warning, error, critical)
- Handles log rotation to prevent excessive disk usage
- Provides methods to retrieve recent threats for the UI
- Uses color-coded console output for immediate visual feedback

### 5. Network Analysis (`network_analyzer.py`)

The `NetworkAnalyzer` class provides network connection monitoring:

- Retrieves active network connections using psutil
- Resolves hostnames for remote connections
- Identifies private vs. public IP addresses
- Retrieves detailed connection information for specific processes

### 6. Process Monitoring (`process_monitor.py`)

The `ProcessMonitor` class tracks system processes:

- Gets information on all running processes
- Retrieves detailed information about specific processes
- Captures process attributes like executable path, command line, and resource usage

### 7. User Interface (`ui.py`)

The `ThreatResponseUI` class implements a Tkinter-based dashboard:

- Displays current system status and threat level
- Shows a scrollable log of detected threats
- Presents a real-time graph of threat score trends
- Provides control buttons for monitoring operations
- Includes system resource usage information
- Offers a configuration interface for threat signatures

### 8. Configuration (`config.py`)

The `SystemConfig` class manages system configuration:

- Loads and merges configuration from JSON files
- Provides default settings when configuration is not available
- Offers hierarchical access to configuration parameters
- Handles configuration updates and persistence

## Installation Requirements

- Python 3.9+
- Required Python packages:
  - psutil
  - matplotlib
  - tkinter (included with standard Python on most platforms)

## Installation

1. Clone the repository or download the source code
2. Install required dependencies:
```
pip install psutil matplotlib
```

## Usage

### Starting the Application

Run the application using:
```
python main.py
```

### Basic Operations

1. **Start Monitoring**: Click the "Start Monitoring" button to begin real-time threat detection
2. **Stop Monitoring**: Click the "Stop Monitoring" button to halt monitoring
3. **Reset Threat Level**: Click the "Reset Threat Level" button to clear the current threat score
4. **Configure Signatures**: Click the "Configure Signatures" button to view and modify threat definitions

### Understanding the Interface

- **System Status**: Displays the current monitoring state and threat level
- **Active Threats**: Shows the number of detected threats
- **Threat Log**: Lists detected threats with timestamps and severity levels
- **Threat Score Trend**: Graphical representation of the threat score over time
- **System Information**: Shows current CPU, memory, disk usage, and active threads

### Customizing Threat Signatures

1. Click the "Configure Signatures" button
2. Edit the JSON configuration in the opened window
3. Click "Save Signatures" to apply changes

## Threat Detection Criteria

### Network Threats

- **Suspicious Ports**: Connections to known backdoor ports (31337, 6667, 8080, 4444, 3389)
- **Blacklisted IPs**: Connections to known malicious IP addresses or ranges

### Process Threats

- **Risky Processes**: Known hacking tools and suspicious applications
- **Process Patterns**: Processes with names matching suspicious patterns

### File Threats

- **Suspicious Extensions**: Files with potentially dangerous extensions
- **Malware Signatures**: Binary patterns indicating malware presence

## Advanced Configuration

### Threat Signatures (`signatures.json`)

The threat signatures are defined in a hierarchical JSON structure:

```json
{
  "network_threats": {
    "suspicious_ports": [31337, 6667, 8080, 4444, 3389],
    "blacklisted_ips": ["185.153.196.74", "91.121.88.14", "45.133.193.142", "185.234.217.0/24"]
  },
  "process_threats": {
    "risky_processes": ["nmap", "metasploit", "hydra", "john", "aircrack", "wireshark", "sqlmap", "nikto"],
    "process_patterns": [".*hack.*", ".*exploit.*", ".*shell.*", ".*reverse.*"]
  },
  "file_threats": {
    "suspicious_extensions": [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".dll", ".jar"],
    "malware_signatures": ["MZ\\x90\\x00\\x03\\x00\\x00\\x00", "#!msfconsole"]
  },
  "network_patterns": {
    "suspicious_domains": [".*torrent.*", ".*proxy.*", ".*anonymizer.*"],
    "tor_exit_nodes": ["185.220.100.0/24", "85.31.186.0/24"]
  }
}
```

### System Configuration (`config.json`)

The system configuration controls operational parameters:

```json
{
  "monitoring": {
    "scan_interval": 5,
    "auto_start": false
  },
  "logging": {
    "log_dir": "logs",
    "max_log_size": 10485760,
    "backup_count": 5
  },
  "threat_detection": {
    "sensitivity": "medium",
    "auto_mitigate": true
  },
  "notifications": {
    "email_alerts": false,
    "email_recipient": "",
    "sms_alerts": false,
    "phone_number": ""
  }
}
```

## Threat Scoring System

The system uses a cumulative threat score from 0-100:

- **0-30**: Normal - No significant threats detected
- **31-70**: Elevated - Suspicious activities detected
- **71-100**: Critical - High probability of malicious activity

Actions that increase the threat score:
- Connection to blacklisted IP: +30 points
- Detection of suspicious port: +20 points
- Detection of suspicious process: +40 points
- Detection of suspicious file: +20-50 points (based on signature severity)

## Logging

Logs are stored in the following locations:
- General application log: `logs/threat_response.log`
- Threat events log: `logs/threat_events.json`

## Architecture

The system uses a multi-threaded architecture:
- Main UI thread for the interface
- Monitoring thread for continuous threat detection
- Thread-safe operations for shared data access

## Performance Considerations

- The monitoring thread runs on a 5-second interval by default
- Log rotation prevents excessive disk usage
- Resource usage is monitored and displayed in the UI

## Security Notes

- The system operates with the permissions of the executing user
- Some operations may require elevated privileges to access certain process details
- The system is designed for monitoring only and does not implement active countermeasures

## Development

### Project Structure

```
dynamic-threat-response/
├── main.py                 # Main entry point and system controller
├── threat_detector.py      # Threat analysis logic
├── threat_signatures.py    # Threat definitions and pattern matching
├── logger.py               # Logging system
├── network_analyzer.py     # Network connection monitoring
├── process_monitor.py      # Process monitoring
├── ui.py                   # User interface
├── config.py               # Configuration management
├── config.json             # System configuration file
├── signatures.json         # Threat signature definitions
└── logs/                   # Log directory
    ├── threat_response.log # General application log
    └── threat_events.json  # Threat event log
```

### Extending the System

1. **Adding new threat types**: Extend the `threat_signatures.py` file with new categories
2. **Implementing new detection methods**: Add methods to the `ThreatDetector` class
3. **Enhancing the UI**: Modify the `ThreatResponseUI` class
4. **Adding notifications**: Implement notification methods in the `main.py` file

## Future Enhancements

Potential areas for future development:

1. **Automated responses**: Implement automatic countermeasures for detected threats
2. **Machine learning**: Add behavior-based anomaly detection
3. **Remote monitoring**: Enable monitoring of multiple systems from a central console
4. **Integration with external security tools**: Add API connections to security services
5. **Expanded notification options**: Implement SMS, email, and mobile app notifications
6. **Advanced visualization**: Add more detailed threat analysis visualizations
7. **File system monitoring**: Add real-time file system change detection

## Contributors
- [@ajitashwathr10](https://github.com/ajitashwathr10)
- [@Kee-rti](https://github.com/Kee-rti)
- [@mansipandey21](https://github.com/mansipandey21)
