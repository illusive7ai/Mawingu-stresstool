
# Mawingu - Network Security Testing Tool
This is a GUI python project that i used as the attackers side for my final year project. This project is to be continued and more functionalities added.

---

## Table of Contents

1. Overview
2. Features
3. System Requirements
4. Installation
5. Usage Guide
6. Module Documentation
7. Screenshots
8. Troubleshooting
9. Security Notice
10. License

---

## Overview

Mawingu stresstool is a comprehensive network security testing tool designed for professional security assessments, penetration testing and network diagnostics. The tool provides three primary attack vectors for testing network infrastructure resilience: ICMP flood testing, DNS stress testing and port scanning capabilities.

This tool is intended for authorized security professionals to test their own infrastructure or systems they have explicit permission to assess.

---

## Features

### Port Scanner Module

- TCP Connect scanning with service detection
- Customizable port ranges with preset configurations
- Multi-threaded scanning for improved performance
- Real-time progress tracking and results display
- Support for common service port identification
- Results export functionality
- Local IP detection

### ICMP Attack Module

- Real ICMP packet generation using native ping commands
- Support for single or multiple targets simultaneously
- Configurable ping intervals for rate control
- Infinite attack mode for stress testing
- Cross-platform compatibility (Windows/Linux/Mac)
- Real-time success/failure statistics
- Terminal-style output with timestamp logging

### DNS Attack Module

- DNS query flooding against target DNS servers
- Support for multiple query types: A, AAAA, MX, TXT, NS
- Configurable timeout settings
- Built-in common DNS server presets
- Infinite attack mode capability
- Response validation and timing metrics
- Progress tracking for finite attacks

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 10/11, Linux (Ubuntu 20.04+), macOS 11+ |
| Processor | Dual-core 2.0 GHz |
| RAM | 4 GB |
| Disk Space | 200 MB |
| Python Version | 3.8 or higher |
| Network | Internet connection for DNS resolution |

### Recommended Requirements

| Component | Recommendation |
|-----------|----------------|
| Operating System | Windows 11 / Ubuntu 22.04 |
| Processor | Quad-core 3.0 GHz |
| RAM | 8 GB |
| Disk Space | 500 MB |
| Python Version | 3.10 or higher |

### Dependencies

The following Python packages are required:

- PyQt5 (GUI framework)
- PyQtWebEngine (for HTML content rendering)

---

## Installation

### Step 1: Install Python

Ensure Python 3.8 or higher is installed on your system. Verify with:

```bash
python --version
```

### Step 2: Clone or Download the Tool

```bash
git clone [repository-url]
cd mawingu
```

### Step 3: Install Dependencies

```bash
pip install PyQt5 PyQtWebEngine
```

### Step 4: Create Assets Directory (Optional)

For custom avatar display, create an `assets` folder in the tool directory and place an `attacker.png` file:

```
mawingu/
├── mawinguatt.py
└── assets/
    └── attacker.png
```

### Step 5: Run the Tool

```bash
python mawinguatt.py
```

---

## Usage Guide

### Launching the Application

Execute the main script to launch the graphical user interface:

```bash
python mawinguatt.py
```

The main dashboard will appear with three navigation options in the sidebar: Port Scanner, ICMP Attack, and DNS Attacks.

### Port Scanner Module

**Purpose:** Identify open ports and running services on target systems.

**Configuration:**

| Field | Description | Example |
|-------|-------------|---------|
| Target | IP address or hostname | 192.168.1.1, localhost |
| Start Port | Beginning port number | 1 |
| End Port | Ending port number | 1024 |
| Scan Type | TCP Connect or SYN Scan | TCP Connect |
| Timeout | Seconds to wait for response | 2 |
| Threads | Concurrent scanning threads | 100 |

**Preset Options:**

- Common: Scans ports 1-1024 (well-known ports)
- All: Scans ports 1-65535 (full range)
- Web: Scans ports 80-8080 (web service ports)

**How to Use:**

1. Navigate to Port Scanner tab
2. Enter target IP address
3. Select port range (manual or preset)
4. Configure scan type and timeout
5. Click "Start Scan"
6. Review results in the terminal window
7. Use "Save Results" to export findings

### ICMP Attack Module

**Purpose:** Test network resilience against ICMP flood attacks.

**Configuration:**

| Field | Description | Example |
|-------|-------------|---------|
| Target(s) | One or more IPs/domains | 8.8.8.8, google.com |
| Count | Number of pings per target | 1000 |
| Infinite | Continuous attack mode | Checkbox |
| Interval | Seconds between pings | 0.1 |

**How to Use:**

1. Navigate to ICMP Attack tab
2. Enter target(s) (comma-separated for multiple)
3. Set ping count or enable Infinite mode
4. Configure interval (lower = higher rate)
5. Click "Start Flood"
6. Monitor statistics and terminal output
7. Click "Stop Flood" to halt

**Important Notes:**

- Minimum interval is 0.05 seconds (20 pings/sec)
- Multiple targets are attacked in round-robin fashion
- Real ICMP packets are sent using system ping command

### DNS Attack Module

**Purpose:** Stress test DNS servers with query floods.

**Configuration:**

| Field | Description | Example |
|-------|-------------|---------|
| DNS Server | Target DNS server IP | 8.8.8.8 |
| Query Type | DNS record type | A, AAAA, MX, TXT, NS |
| Attacks | Number of queries to send | 1000 |
| Infinite | Continuous attack mode | Checkbox |
| Timeout | Seconds to wait for response | 2 |

**Common DNS Servers:**

| Provider | Primary DNS | Secondary DNS |
|----------|-------------|---------------|
| Google | 8.8.8.8 | 8.8.4.4 |
| Cloudflare | 1.1.1.1 | 1.0.0.1 |
| Quad9 | 9.9.9.9 | - |
| OpenDNS | 208.67.222.222 | 208.67.220.220 |

**How to Use:**

1. Navigate to DNS Attacks tab
2. Enter target DNS server IP
3. Select query type from dropdown
4. Set attack count or enable Infinite mode
5. Configure timeout value
6. Click "Start Attack"
7. Monitor success/failure statistics
8. Click "Stop Attack" to halt

---

## Module Documentation

### PortScanWorker Class

**Purpose:** Background thread for port scanning operations.

**Signals:**
- `port_update(port, status, service)` - Emitted when a port is scanned
- `scan_progress(current, total)` - Updates progress bar
- `scan_complete(open_ports)` - Called when scan finishes
- `scan_started(target, start_port, end_port)` - Emitted at scan initiation

**Parameters:**
- `target_ip`: Target system IP address
- `start_port`: Beginning port number
- `end_port`: Ending port number
- `scan_type`: "connect" or "syn"
- `timeout`: Response wait time in seconds
- `max_threads`: Concurrent scanning threads

### PingWorker Class

**Purpose:** Background thread for ICMP flood operations.

**Signals:**
- `ping_update(sent, success, failed)` - Updates statistics
- `ping_reply(target, reply_text)` - Individual ping result
- `finished()` - Emitted when flood completes

**Parameters:**
- `targets`: List of target IPs/domains
- `ping_count`: Number of pings (-1 for infinite)
- `interval`: Seconds between pings

### DNSAttackWorker Class

**Purpose:** Background thread for DNS attack operations.

**Signals:**
- `attack_update(sent, success, failed)` - Statistics update
- `attack_response(target, response, query_type)` - Individual response
- `attack_progress(current, total)` - Progress update
- `attack_started(target, query_type, total)` - Attack initiation
- `attack_complete(stats)` - Attack completion

**Parameters:**
- `dns_server`: Target DNS server IP
- `query_type`: DNS record type (A, AAAA, MX, TXT, NS)
- `attack_count`: Number of attacks (-1 for infinite)
- `timeout`: Response wait time in seconds

---

## Screenshots

Screenshot locations are provided below. Insert your captured images at the marked positions.

### Screenshot 1: Main Dashboard

[main.jpg]

*Description: The main application window showing the sidebar navigation and the active tab content area. The dark theme interface displays the Port Scanner module as the default view.*

**Capture instructions:** Launch the application and capture the entire window showing the Port Scanner tab with its statistics cards, control panel, and terminal output area.

---

### Screenshot 2: Port Scanner Results

[portscan]

*Description: Port scanner module displaying scan results with open ports highlighted. The terminal shows discovered services and the statistics cards display scanned ports count, open ports, and closed ports.*

**Capture instructions:** Run a port scan against a local or test IP address. Wait for scan completion and capture the results showing open ports in green with service names.

---

### Screenshot 3: ICMP Attack Configuration

[icmp.jpg]

*Description: ICMP Attack tab showing configuration options including target input field with multiple targets, count setting with infinite checkbox, and interval slider/input.*

**Capture instructions:** Navigate to the ICMP Attack tab. Enter multiple test targets (e.g., 8.8.8.8, 1.1.1.1) and show the configuration panel with all controls visible.

---

### Screenshot 4: ICMP Attack Active

[INSERT SCREENSHOT HERE]

*Description: ICMP Attack module during an active flood. The statistics cards show increasing numbers, the terminal displays ping responses with timestamps, and the stop button is highlighted.*

**Capture instructions:** Start an ICMP flood attack against a test target. Capture the screen during the attack showing real-time statistics updates and terminal output.

---

### Screenshot 5: DNS Attack Configuration

[INSERT SCREENSHOT HERE]

*Description: DNS Attacks tab with DNS server dropdown expanded showing common server options. Query type selector displays available record types.*

**Capture instructions:** Navigate to the DNS Attacks tab. Click the DNS server dropdown to show the list of common DNS servers. Expand the query type combo box to show all options.

---

### Screenshot 6: DNS Attack Results

[INSERT SCREENSHOT HERE]

*Description: DNS attack results showing successful and failed queries. The terminal displays response times and the statistics cards show query counts.*

**Capture instructions:** Run a DNS attack against a test DNS server. Capture the results showing the terminal output with colored success/failure messages and updated statistics.

---

### Screenshot 7: Results Export Dialog

[INSERT SCREENSHOT HERE]

*Description: File save dialog appearing after clicking the Save Results button. The dialog shows the default filename with timestamp.*

**Capture instructions:** After completing any attack or scan, click the Save Results button. Capture the native file save dialog showing the proposed filename.

---

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| Application fails to start | Missing PyQt5 | Run `pip install PyQt5 PyQtWebEngine` |
| Port scan shows no results | Firewall blocking | Disable firewall temporarily or add exception |
| ICMP attack fails | Administrative privileges required | Run as administrator/root |
| DNS timeout errors | Network connectivity issues | Verify network connection and DNS server availability |
| SYN scan not working | Requires admin privileges | Use TCP Connect scan or run as administrator |

### Platform-Specific Notes

**Windows:**
- ICMP attacks use native ping.exe
- Run as administrator for SYN scan functionality
- Firewall may block outbound ICMP

**Linux:**
- May require sudo for ICMP operations
- Install python3-pyqt5 and python3-pyqt5.webengine via package manager
- Raw socket operations require root privileges

**macOS:**
- May require sudo for certain operations
- PyQt5 installation may need Homebrew

---

## Security Notice

**IMPORTANT: This tool is for authorized security testing only.**

Mawingu stresstool is designed to help security professionals test network infrastructure resilience. Users must:

1. Obtain explicit written permission before testing any system
2. Comply with all applicable laws and regulations
3. Use the tool only on systems they own or are authorized to test
4. Not use this tool for malicious purposes or unauthorized access

The developers assume no liability for misuse of this tool. Unauthorized network testing may violate computer fraud and abuse laws in many jurisdictions.

---

## License

This tool is provided for educational and professional security testing purposes only.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Current | Initial release with Port Scanner, ICMP Attack and DNS Attack modules |

---

## Contact and Support

For issues, feature requests or security concerns, please document the problem including:

- Operating system version
- Python version
- Complete error message or screenshot
- Steps to reproduce the issue

---

## Acknowledgments

- Built with PyQt5 framework
- Icons and styling inspired by modern security tools
- DNS packet construction based on RFC 1035 specifications

---
