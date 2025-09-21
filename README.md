# CCDC Test Scripts - Quick Reference Guide

A collection of automated scripts for setting up and managing cybersecurity tools, optimized for CCDC (Collegiate Cyber Defense Competition) environments.

## 📋 Script Overview

| Script | Purpose | Quick Run |
|--------|---------|-----------|
| `install_vpns_2.sh` | VPN Server Setup | `sudo ./Version_2/install_vpns_2.sh` |
| `vpn_client_connect_2.sh` | VPN Client Connection | `sudo ./Version_2/vpn_client_connect_2.sh` |
| `FIM.sh` | File Integrity Monitoring | `sudo ./Version_1/FIM.sh` |
| `Docker_install.sh` | Docker Installation | `sudo ./Version_1/Docker_install.sh` |
| `InstallPowerShell.sh` | PowerShell Setup | `sudo ./Version_1/InstallPowerShell.sh` |
| `IDS.sh` | IDS/IPS Management | `sudo ./Version_1/IDS.sh` |
| `Honeypot.sh` | Honeypot Setup | `sudo ./Version_1/Honeypot.sh` |
| `SubnetAndPingConfigs.sh` | Subnet and Ping Configurations | `sudo ./Version_1/SubnetAndPingConfigs.sh` |
| `File_Transfer_Server4.sh` | File Transfer Servers | `sudo ./Version_2/File_Transfer_Server4.sh` |
| `file_transfer_client2.sh` | File Transfer Client | `./Version_2/file_transfer_client2.sh` |
| `Network_Scanner_Tshark.sh` | Network Scanning with Tshark | `sudo ./Version_1/Network_Scanner_Tshark.sh` |
| `PCAP_Analyzer_Tshark.sh` | PCAP File Analysis | `sudo ./Version_1/PCAP_Analyzer_Tshark.sh` |
| `system_enumerator.sh` | System Enumeration | `sudo ./Version_1/system_enumerator.sh` |

---

## 🔧 Detailed Script Guide

### 1. VPN Scripts

#### `install_vpns_2.sh` - VPN Server Manager
**What it does:** Installs and manages VPN servers (OpenVPN, WireGuard, SoftEther)

**How to run:**
```bash
sudo ./Version_2/install_vpns_2.sh
```

**Menu Options:**
- 1) Install a VPN
- 2) Uninstall a VPN
- 3) Show connection instructions
- 4) Show active VPN services
- 5) Certificate & User Management
- 6) Run VPN Diagnostics
- 7) Integration & Testing Help

**Example Usage:**
- Choose option 1 → Select OpenVPN → Follow prompts
- Choose option 5 → Generate client certificates for team members

#### `vpn_client_connect_2.sh` - VPN Client Connector
**What it does:** Connects to VPN servers and manages client configurations

**How to run:**
```bash
sudo ./Version_2/vpn_client_connect_2.sh
```

**Menu Options:**
- 1) Connect to OpenVPN Server
- 2) Connect to WireGuard Server
- 3) Connect to SoftEther Server
- 4) Detect Server VPN Services
- 5) Test Server Connectivity
- 6) Exit

**Example Usage:**
- Choose option 4 → Enter server IP to auto-detect available VPNs
- Choose option 1 → Enter server details and certificate paths

---

### 2. Security Monitoring Scripts

#### `FIM.sh` - File Integrity Monitor
**What it does:** Monitors file changes using SHA256 hashes

**How to run:**
```bash
sudo ./Version_1/FIM.sh
```

**Menu Options:**
- 1) Start monitoring a new path
- 2) List active monitors
- 3) Stop monitoring a path
- 4) View live logs for a monitor
- 5) Exit

**Example Usage:**
- Choose option 1 → Enter `/etc` to monitor system config files
- Choose option 4 → View real-time change logs

#### `IDS.sh` - IDS/IPS Manager
**What it does:** Installs and configures Suricata IDS/IPS

**How to run:**
```bash
sudo ./Version_1/IDS.sh
```

**Menu Options:**
- 1) Install Suricata
- 2) Uninstall Suricata
- 3) Adjust Service
- 4) Quit

**Example Usage:**
- Choose option 1 → Select IDS or IPS mode → Configure network interface

#### `Honeypot.sh` - Honeypot Manager
**What it does:** Sets up Endlessh SSH tarpit honeypot

**How to run:**
```bash
sudo ./Version_1/Honeypot.sh
```

**Menu Options:**
- 1) Install Endlessh
- 2) Uninstall Endlessh
- 3) Adjust Service
- 4) Export Logs for IR
- 5) Quit

**Example Usage:**
- Choose option 1 → Installs and configures SSH honeypot on port 2222

---

### 3. Infrastructure Scripts

#### `Docker_install.sh` - Docker Manager
**What it does:** Installs/uninstalls Docker Engine

**How to run:**
```bash
sudo ./Version_1/Docker_install.sh
```

**Menu Options:**
- 1) Install Docker
- 2) Uninstall Docker
- 3) Quit

**Example Usage:**
- Choose option 1 → Installs Docker and adds user to docker group

#### `InstallPowerShell.sh` - PowerShell Installer
**What it does:** Installs Microsoft PowerShell on Linux

**How to run:**
```bash
sudo ./Version_1/InstallPowerShell.sh
```

**What it does:**
- Auto-detects if PowerShell is installed
- Installs if missing, offers uninstall if present
- Sets up Microsoft repository

**Example Usage:**
- Run script → Follow prompts → Use `pwsh` command to start PowerShell

#### `SubnetAndPingConfigs.sh` - Subnet and Ping Configurations
**What it does:** Configures subnets and ping settings for network management

**How to run:**
```bash
sudo ./Version_1/SubnetAndPingConfigs.sh
```

**Example Usage:**
- Run script → Configure subnet settings and ping parameters

#### `File_Transfer_Server4.sh` - File Transfer Manager
**What it does:** Manages FTP, SFTP, and TFTP servers

**How to run:**
```bash
sudo ./Version_2/File_Transfer_Server4.sh
```

**Menu Options:**
- 1) Install a service
- 2) Uninstall a service

**Sub-options:**
- FTP (vsftpd)
- SFTP (OpenSSH)
- TFTP (tftpd-hpa)

**Example Usage:**
- Choose option 1 → Select FTP → Installs and starts FTP server on port 21

#### `file_transfer_client2.sh` - File Transfer Client
**What it does:** Connects to and transfers files with FTP/SFTP/TFTP servers

**How to run:**
```bash
./Version_2/file_transfer_client2.sh
```

**Menu Options:**
- 1) Connect to FTP Server
- 2) Connect to SFTP Server
- 3) Connect to TFTP Server
- 4) Test Server Connectivity
- 5) Show Connection Status
- 6) Exit

**Supported Operations:**
- **FTP:** Upload/download files, list directories, create directories
- **SFTP:** Interactive session with full file operations
- **TFTP:** Simple upload/download operations

**Example Usage:**
- Choose option 1 → Enter FTP server details → Upload/download files
- Choose option 4 → Test connectivity to multiple servers

---

### 4. Network Analysis Scripts

#### `Network_Scanner_Tshark.sh` - Network Scanner with Tshark
**What it does:** Performs advanced network scans and captures using Tshark for threat hunting

**How to run:**
```bash
sudo ./Version_1/Network_Scanner_Tshark.sh
```

**Menu Options:**
- 1) List Available Interfaces
- 2) Basic Live Capture
- 3) Capture and Save to PCAP
- 4) Read and Display from PCAP
- 5) Filter HTTP Traffic (Live)
- 6) Filter DNS Queries (Live)
- 7) TCP Conversation Statistics
- 8) Extract Credentials
- 9) Follow TCP Stream (from PCAP)
- 10) Custom Tshark Command

**Example Usage:**
- Choose option 3 → Select interface and duration → Saves PCAP to /tmp/tshark_logs/
- Choose option 5 → Monitor live HTTP traffic for anomalies

#### `PCAP_Analyzer_Tshark.sh` - PCAP File Analyzer
**What it does:** Analyzes saved PCAP files with various filters for incident response

**How to run:**
```bash
sudo ./Version_1/PCAP_Analyzer_Tshark.sh
```

**Filter Options:**
- HTTP Traffic
- DNS Queries
- Port-based filtering
- IP-based filtering
- TCP SYN/ACK analysis
- Credential extraction
- TCP conversation statistics
- Custom filters

**Example Usage:**
- Run script → Select PCAP file → Choose filter (e.g., HTTP) → View tabular results
- Option to save filtered results to file

#### `system_enumerator.sh` - System Enumerator
**What it does:** Performs comprehensive system enumeration for security assessment

**How to run:**
```bash
sudo ./Version_1/system_enumerator.sh
```

**Enumeration Categories:**
- System Information
- User and Group Details
- Network Configuration
- Running Processes
- Installed Packages
- File System Analysis
- Security Settings

**Example Usage:**
- Run script → Select enumeration type → Review output for security insights

---

## 🚀 Quick Start Examples

### Basic VPN Setup (Server + Client)
```bash
# On VPN Server
sudo ./Version_2/install_vpns_2.sh
# → 1 (Install) → 1 (OpenVPN) → Follow prompts

# On Client Machine
sudo ./Version_2/vpn_client_connect_2.sh
# → 4 (Detect) → Enter server IP
# → 1 (OpenVPN) → Enter details
```

### Security Monitoring Setup
```bash
# File Integrity Monitoring
sudo ./Version_1/FIM.sh
# → 1 (Start) → Enter path like /etc

# IDS Setup
sudo ./Version_1/IDS.sh
# → 1 (Install) → Choose IDS mode
```

### Infrastructure Setup
```bash
# Docker
sudo ./Version_1/Docker_install.sh
# → 1 (Install)

# PowerShell
sudo ./Version_1/InstallPowerShell.sh
# → Auto-installs if missing
```

### File Transfer Setup
```bash
# First, set up a file server
sudo ./Version_2/File_Transfer_Server4.sh
# → 1 (Install) → 1 (FTP) → Installs FTP server

# Then connect and transfer files
./Version_2/file_transfer_client2.sh
# → 1 (FTP) → Enter server details → Upload/download files
```

### Network Analysis Setup
```bash
# Network Scanning
sudo ./Version_1/Network_Scanner_Tshark.sh
# → 3 (Capture to PCAP) → Select interface → Saves capture

# PCAP Analysis
sudo ./Version_1/PCAP_Analyzer_Tshark.sh
# → Select saved PCAP → Choose filter → Analyze traffic

# System Enumeration
sudo ./Version_1/system_enumerator.sh
# → Select enumeration category → Review system details
```

---

## ⚠️ Important Notes

### Prerequisites
- **Root Access:** All scripts require `sudo` privileges
- **Package Managers:** Support for `apt` (Ubuntu/Debian) and `dnf` (Fedora/RHEL)
- **Internet:** Required for downloading packages
- **CCDC Environment:** Optimized for competition VMs

### Common Requirements
- Run all scripts as root: `sudo ./script.sh`
- Ensure internet connectivity for package downloads
- Check firewall settings (especially for CCDC Palo Alto configs)
- Review logs after installation for any issues

### CCDC-Specific Tips
- Test all installations in isolated environments first
- Document IP addresses and ports for team coordination
- Use certificate management for secure team access
- Monitor logs for security incidents
- Backup configurations before competitions

---

## 🔍 Troubleshooting

### Common Issues
- **Permission Denied:** Run with `sudo`
- **Package Not Found:** Check internet connection
- **Service Won't Start:** Check system logs with `journalctl`
- **Port Conflicts:** Verify ports aren't already in use

### Getting Help
- Check script logs in `/var/log/`
- Run diagnostic options where available
- Test in clean VM environment
- Review CCDC documentation

---

## 📝 Script Compatibility

| Script | Debian/Ubuntu | Fedora/RHEL | Root Required | Internet Required |
|--------|---------------|-------------|---------------|-------------------|
| VPN Scripts | ✅ | ✅ | ✅ | ✅ |
| FIM | ✅ | ✅ | ✅ | ❌ |
| Docker | ✅ | ✅ | ✅ | ✅ |
| PowerShell | ✅ | ✅ | ✅ | ✅ |
| IDS | ✅ | ✅ | ✅ | ✅ |
| Honeypot | ✅ | ✅ | ✅ | ✅ |
| File Transfer | ✅ | ✅ | ✅ | ✅ |
| File Transfer Client | ✅ | ✅ | ❌ | ❌ |
| Network Scanner | ✅ | ✅ | ✅ | ❌ |
| PCAP Analyzer | ✅ | ✅ | ❌ | ❌ |
| System Enumerator | ✅ | ✅ | ✅ | ❌ |

---

## 🎯 CCDC Competition Use

### Recommended Setup Order
1. **Infrastructure:** Docker, PowerShell (if needed)
2. **Security:** IDS, Honeypot, FIM
3. **Services:** File Transfer Servers
4. **Connectivity:** VPN Server + Client connections
5. **Analysis:** Network Scanner, PCAP Analyzer, System Enumerator

### Team Coordination
- Use VPN scripts for secure team communication
- Share certificates securely between team members
- Monitor honeypot and IDS logs for red team activity
- Use FIM to detect unauthorized file changes
- Employ network analysis tools for traffic inspection and threat hunting
- Run system enumeration to baseline and monitor system state

---

*For detailed documentation and advanced features, see the comprehensive README or run scripts with `--help` where available.*