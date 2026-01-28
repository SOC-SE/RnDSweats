# CCDC Development Toolkit - AI Development Guidelines

> **Purpose**: Comprehensive guidelines for AI-assisted development of CCDC (Collegiate Cyber Defense Competition) security scripts and tooling.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Competition Context](#2-competition-context)
3. [Repository Structure](#3-repository-structure)
4. [Script Categories](#4-script-categories)
5. [Development Workflow](#5-development-workflow)
6. [Testing Requirements](#6-testing-requirements)
7. [Script Standards](#7-script-standards)
8. [Vagrant Testing Environment](#8-vagrant-testing-environment)
9. [Approval Requirements](#9-approval-requirements)
10. [Salt-GUI Integration Considerations](#10-salt-gui-integration-considerations)
11. [Target Systems Reference](#11-target-systems-reference)

---

## 1. Project Overview

### What Is This Project?

This is a comprehensive toolkit for CCDC (Collegiate Cyber Defense Competition) preparation, containing scripts, tools, and configurations for:
- System hardening (Linux and Windows)
- Threat hunting and incident response
- Security monitoring and SIEM deployment
- Network auditing and enumeration
- Service-specific hardening and configuration
- Network appliance configuration (VyOS, Palo Alto, Cisco FTD)

### Core Principles

| Principle | Description |
|-----------|-------------|
| **Competition-Ready** | Scripts must work under time pressure with minimal configuration |
| **Cross-Platform** | Support multiple Linux distributions and Windows versions |
| **Standalone** | Scripts should work independently without external dependencies when possible |
| **Measurable** | Track execution time and resource impact |
| **Documented** | Clear usage instructions and expected outcomes |
| **Tested** | All scripts must pass Vagrant testing before deployment |

### Repository Information

- **Repository**: github.com/SOC-SE/RnDSweats
- **Branch**: Development
- **Related Project**: Salt-GUI at /home/sam/SaltGUI/salt-gui (for Salt integration)

---

## 2. Competition Context

### MWCCDC (Midwest Collegiate Cyber Defense Competition)

**Competition Environment:**
- 6-8 hour timed competitions
- Mixed Linux and Windows systems
- Network appliances (VyOS, Palo Alto, Cisco FTD)
- Active red team adversaries
- Service availability scoring
- Business task (inject) completion

**2026 MWCCDC Qualifier Topology:**

| VM | OS/Version | Role | Services |
|----|------------|------|----------|
| Ubuntu Ecom | Ubuntu 24.04 | E-commerce Server | Web (HTTP/HTTPS) |
| Fedora Webmail | Fedora 42 | Webmail Server | SMTP, POP3 |
| Splunk | Oracle Linux 9.2 | SIEM | Splunk 10.0.2 |
| Ubuntu Wkst | Ubuntu 24.04 | Workstation | User workstation |
| AD/DNS | Windows Server 2019 | Domain Controller | AD, DNS |
| Web Server | Windows Server 2019 | Web Server | IIS |
| FTP Server | Windows Server 2022 | File Server | FTP |
| Windows Wkst | Windows 11 24H2 | Workstation | User workstation |
| Palo Alto | PAN-OS | Firewall | Network security |
| Cisco FTD | FTD 7.2.9 | Firewall | Network security |
| VyOS Router | VyOS 1.4.3 | Router | Routing, NAT |

**Key Constraints:**
- Scripts must NOT be topology-specific (different IPs, subnets per competition)
- Scripts CAN be box/OS-specific
- SSH may be disabled during competition
- Internet access may be limited
- Pre-compromised systems are common

---

## 3. Repository Structure

### Current Directory Layout

```
CCDC-Development/
├── .claude/                    # Claude Code configuration
│   ├── CLAUDE.md              # This file - AI guidelines
│   └── settings.local.json    # MCP server settings
├── vagrant/                    # Vagrant testing environment
│   └── Vagrantfile            # VM definitions
├── docs/                       # Documentation
├── testing/                    # Test results and reports
│
├── LinuxDev/                   # Linux hardening and security scripts
├── Windows Branch/             # Windows scripts and configurations
├── Tools/                      # Tool-specific scripts
│   ├── Wazuh/                 # Wazuh SIEM agent/server setup
│   ├── Splunk/                # Splunk forwarder/server setup
│   ├── Suricata/              # IDS configuration
│   ├── Auditd/                # Linux auditing
│   ├── FireJail/              # Application sandboxing
│   ├── HAProxy/               # Load balancer configuration
│   ├── LinuxAV/               # ClamAV setup
│   ├── MySQL/                 # Database backup/hardening
│   ├── VyOS/                  # VyOS router scripts
│   └── Yara/                  # Malware detection rules
├── SaltyBoxes/                 # Salt-related scripts
│   └── CustomScripts/         # Scripts deployable via Salt
├── PaloAlto/                   # Palo Alto firewall scripts
├── Liaison/                    # Network tools and utilities
├── Alpine/                     # Alpine Linux specific
├── AlpineDev/                  # Alpine development
├── Archive/                    # Deprecated/old scripts
├── misc/                       # Miscellaneous scripts
└── Gentoo(fml)/               # Gentoo specific (low priority)
```

### Script Categories

| Category | Directory | Purpose |
|----------|-----------|---------|
| **Hardening** | LinuxDev/, Windows Branch/ | System hardening scripts |
| **Monitoring** | Tools/Wazuh/, Tools/Splunk/, Tools/Suricata/ | SIEM and monitoring setup |
| **Auditing** | LinuxDev/, Tools/Auditd/ | System and security auditing |
| **Threat Hunting** | SaltyBoxes/CustomScripts/ | Persistence and process hunting |
| **Network** | Liaison/, PaloAlto/, Tools/VyOS/ | Network tools and firewall configs |
| **Database** | Tools/MySQL/ | Database security and backup |
| **Service-Specific** | Various | Apache, NGINX, mail, etc. |

---

## 4. Script Categories

### 4.1 System Hardening

**Linux Hardening Scripts:**
- `generalLinuxHarden.sh` - Comprehensive Linux hardening
- `ssh_harden.sh` - SSH configuration hardening
- `smbHarden.sh` - Samba hardening
- `harden_web.sh` - Web server hardening
- `mail_hardener.sh` / `mail_hardener_fedora.sh` - Mail server hardening
- `opencart_hardener.sh` - OpenCart specific hardening
- `firewallGenerator.sh` - iptables/firewalld rule generation
- `fail2ban_script.sh` - Fail2ban setup

**Windows Hardening Scripts:**
- `startscript*.ps1` - Windows startup hardening scripts
- `quickHarden.ps1` - Quick Windows hardening
- `GPO_Import*.ps1` - Group Policy deployment

### 4.2 Threat Hunting & Detection

- `persistenceHunter.sh` / `persistenceHunter.ps1` - Find persistence mechanisms
- `processHunter.sh` / `processHunter.ps1` - Suspicious process detection
- `rootkitDetectionInstall.sh` - Rootkit detection (rkhunter, chkrootkit)
- `masterEnum.sh` - Comprehensive system enumeration

### 4.3 Auditing

- `serviceAudit.sh` - Service enumeration and auditing
- `networkAudit.sh` / `networkAudit.ps1` - Network connection auditing
- `userAudit.ps1` - User account auditing
- `logAnalysis.sh` - Log analysis and review

### 4.4 Monitoring & SIEM

- `WazuhLinuxAgentSetup.sh` - Wazuh agent deployment
- `splunkForwarderLinuxGeneral.sh` - Splunk forwarder setup
- `windowSplunkForwarderGeneral.ps1` - Windows Splunk forwarder
- `SplunkServerInstall.sh` - Splunk server installation
- `suricataSetup.sh` - Suricata IDS deployment
- `auditdSetup.sh` - Linux audit daemon configuration

### 4.5 Network & Infrastructure

- `vyosEnumerate.sh` - VyOS router enumeration
- `paloSetup.sh` - Palo Alto configuration
- `haproxyConfig.sh` - HAProxy load balancer
- `dnsServerInstall.sh` - DNS server setup

### 4.6 Utilities

- `normalizeTools.sh` - Install standard security tools
- `generalUpgrade.sh` / `oracleUpgrade.sh` - System updates
- `dockerInstall.sh` - Docker installation
- `elkInstall.sh` / `elkAgent.sh` - ELK stack deployment

---

## 5. Development Workflow

### Standard Workflow

1. **Research Phase**
   - Understand the requirement
   - Check existing scripts for similar functionality
   - Research best practices for the target system

2. **Development Phase**
   - Create/modify scripts following standards (Section 7)
   - Include error handling and logging
   - Add usage documentation in script header

3. **Testing Phase**
   - Test in Vagrant environment
   - Document execution time and resource usage
   - Verify on all applicable target systems
   - Record test results

4. **Review Phase**
   - Request user approval before committing
   - Document any Salt-GUI integration opportunities

5. **Deployment Phase**
   - Commit with descriptive message
   - Push to Development branch (with approval)

### Batch Testing Approach

When testing multiple scripts:
1. Group non-interfering scripts together
2. Start VMs once, run all compatible tests
3. Record results for each script
4. Minimize VM restarts to save time

---

## 6. Testing Requirements

### Mandatory Testing

All scripts MUST be tested on applicable target systems:

| Target | Required | Notes |
|--------|----------|-------|
| Ubuntu 24.04 | Yes | Primary Linux target |
| Fedora 42 | Yes | RHEL-family testing |
| Rocky Linux 9 | Yes | Enterprise Linux testing |
| Oracle Linux 9 | Yes | Splunk server OS |
| Debian 12 | Yes | Debian-family testing |
| Windows Server 2019 | Yes | AD/DNS, Web server |
| Windows Server 2022 | Yes | FTP server |
| Windows 11 | Yes | Workstation |
| Alpine Linux | No | Optional, document if tested |
| VyOS | Yes* | For network scripts only |

### Test Metrics to Record

For each script test, document:

```yaml
script: <script_name>
target_os: <os_name>
test_date: <YYYY-MM-DD>
result: PASS | FAIL | PARTIAL
execution_time: <seconds>
resource_impact:
  cpu_peak: <percentage>
  ram_usage: <MB>
  disk_usage: <MB>
  network_usage: <MB, if applicable>
notes: <any issues or observations>
```

### Test Result Location

Store test results in: `/home/sam/CCDC-Development/testing/`

Format: `<script_name>_<date>.yaml`

---

## 7. Script Standards

### Linux Scripts (Bash)

```bash
#!/bin/bash
# ==============================================================================
# Script Name: script_name.sh
# Description: Brief description of what this script does
# Author: [Author Name]
# Date: YYYY-MM-DD
# Version: 1.0
#
# Usage:
#   ./script_name.sh [options]
#
# Options:
#   -h, --help     Show this help message
#   -v, --verbose  Enable verbose output
#   -d, --dry-run  Show what would be done without making changes
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#
# Exit Codes:
#   0 - Success
#   1 - General error
#   2 - Missing dependencies
#   3 - Permission denied
#
# ==============================================================================

set -euo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Logging Functions ---
log()   { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $1"; }
debug() { [[ "${VERBOSE:-0}" == "1" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"; }

# --- Utility Functions ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 3
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
        OS_VERSION="${VERSION_ID%%.*}"
        OS_FAMILY=""
        case "$ID" in
            ubuntu|debian) OS_FAMILY="debian" ;;
            fedora|rhel|centos|rocky|alma|ol|oracle) OS_FAMILY="rhel" ;;
            alpine) OS_FAMILY="alpine" ;;
            *) OS_FAMILY="unknown" ;;
        esac
    else
        error "Cannot detect OS"
        exit 1
    fi
}

# --- Main Logic ---
main() {
    check_root
    detect_os
    log "Starting $SCRIPT_NAME on $OS_ID $OS_VERSION"

    # Script logic here

    log "Completed successfully"
}

main "$@"
```

### Windows Scripts (PowerShell)

```powershell
<#
.SYNOPSIS
    Brief description of the script

.DESCRIPTION
    Detailed description of what this script does, including:
    - Key features
    - System requirements
    - Expected outcomes

.PARAMETER ParameterName
    Description of the parameter

.EXAMPLE
    .\Script-Name.ps1
    Basic usage example

.EXAMPLE
    .\Script-Name.ps1 -Verbose -WhatIf
    Advanced usage example

.NOTES
    Author: [Author Name]
    Date: YYYY-MM-DD
    Version: 1.0

    Supported Systems:
    - Windows Server 2019, 2022
    - Windows 10, 11

    Exit Codes:
    0 - Success
    1 - General error
    2 - Missing dependencies
    3 - Permission denied
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExampleParam = "default",

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptName = $MyInvocation.MyCommand.Name

# --- Logging Functions ---
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $colors = @{
        "INFO" = "Green"
        "WARN" = "Yellow"
        "ERROR" = "Red"
        "DEBUG" = "Cyan"
    }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

# --- Utility Functions ---
function Test-Administrator {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    return @{
        Name = $os.Caption
        Version = $os.Version
        BuildNumber = $os.BuildNumber
        IsServer = $os.ProductType -ne 1
    }
}

# --- Main Logic ---
function Main {
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator" "ERROR"
        exit 3
    }

    $osInfo = Get-OSInfo
    Write-Log "Starting $ScriptName on $($osInfo.Name)"

    # Script logic here

    Write-Log "Completed successfully"
}

Main
```

---

## 8. Vagrant Testing Environment

### Overview

The Vagrant environment mirrors the MWCCDC competition topology for realistic testing.

### Available VMs

| VM Name | Box | IP Address | Purpose |
|---------|-----|------------|---------|
| ubuntu-ecom | ubuntu/jammy64 | 192.168.56.11 | Ubuntu 24.04 Server |
| fedora-webmail | generic/fedora42 | 192.168.56.12 | Fedora 42 Server |
| splunk-oracle | generic/oracle9 | 192.168.56.13 | Oracle Linux 9 + Splunk |
| ubuntu-wkst | ubuntu/jammy64 | 192.168.56.14 | Ubuntu Workstation |
| rocky-server | generic/rocky9 | 192.168.56.15 | Rocky Linux 9 |
| debian-server | debian/bookworm64 | 192.168.56.16 | Debian 12 Server |
| win-server-2019 | gusztavvargadr/windows-server-2019-standard | 192.168.56.21 | Windows Server 2019 |
| win-server-2022 | gusztavvargadr/windows-server-2022-standard | 192.168.56.22 | Windows Server 2022 |
| win11-wkst | gusztavvargadr/windows-11 | 192.168.56.23 | Windows 11 Workstation |
| vyos-router | vyos/current | 192.168.56.1 | VyOS Router |

### Vagrant Commands

```bash
# Start all VMs
cd /home/sam/CCDC-Development/vagrant
vagrant up

# Start specific VM
vagrant up ubuntu-ecom

# SSH into Linux VM
vagrant ssh ubuntu-ecom

# RDP/WinRM into Windows VM
vagrant rdp win-server-2019

# Run command on VM
vagrant ssh ubuntu-ecom -c "sudo ./script.sh"

# Sync files to VM
vagrant rsync ubuntu-ecom

# Destroy and recreate
vagrant destroy ubuntu-ecom -f && vagrant up ubuntu-ecom
```

### Testing Scripts on VMs

1. Copy script to VM:
   ```bash
   vagrant upload /path/to/script.sh /tmp/script.sh ubuntu-ecom
   ```

2. Execute script:
   ```bash
   vagrant ssh ubuntu-ecom -c "sudo bash /tmp/script.sh"
   ```

3. For Windows:
   ```bash
   vagrant winrm win-server-2019 -c "powershell -File C:\Temp\script.ps1"
   ```

---

## 9. Approval Requirements

### Actions Requiring User Approval

1. **Git Operations**
   - `git commit` - Always require approval
   - `git push` - Always require approval
   - `git merge` - Always require approval

2. **File Operations Outside Project**
   - Editing files outside `/home/sam/CCDC-Development/`
   - Deleting any files outside the project directory

3. **System Changes**
   - Installing packages on the host system
   - Modifying system configuration files

### Actions NOT Requiring Approval

- Reading files anywhere
- Running Vagrant commands
- Creating/editing files within the project directory
- Running tests
- Web searches and documentation lookups

---

## 10. Salt-GUI Integration Considerations

### When to Consider Salt Integration

Scripts that would benefit from Salt-GUI integration:
- Scripts that need to run on multiple systems simultaneously
- Hardening scripts that should be deployed fleet-wide
- Monitoring agent installations
- Audit scripts that collect data from multiple systems

### How to Flag for Salt Integration

When creating or reviewing a script that would translate well to Salt:

1. Add a comment in the script header:
   ```bash
   # SALT-GUI-CANDIDATE: This script could be deployed via Salt-GUI
   # Salt module suggestion: cmd.script or state.apply
   ```

2. Note in test documentation:
   ```yaml
   salt_integration:
     recommended: true
     salt_module: cmd.script
     notes: "Would benefit from parallel execution across fleet"
   ```

### Salt-GUI Project Location

Related Salt-GUI project: `/home/sam/SaltGUI/salt-gui`

Scripts suitable for Salt deployment can be copied to:
- `/home/sam/SaltGUI/salt-gui/scripts/linux/` (Linux scripts)
- `/home/sam/SaltGUI/salt-gui/scripts/windows/` (Windows scripts)

---

## 11. Target Systems Reference

### Linux Distributions

| Distribution | Version | Package Manager | Init System | Notes |
|--------------|---------|-----------------|-------------|-------|
| Ubuntu | 24.04 LTS | apt | systemd | Primary target |
| Fedora | 42 | dnf | systemd | Bleeding edge packages |
| Rocky Linux | 9 | dnf | systemd | RHEL clone |
| Oracle Linux | 9 | dnf | systemd | Splunk server |
| Debian | 12 | apt | systemd | Stable server |
| Alpine | 3.19+ | apk | OpenRC | Lightweight, optional |

### Windows Versions

| Version | Type | Notes |
|---------|------|-------|
| Windows Server 2019 | Server | AD/DNS, Web server |
| Windows Server 2022 | Server | FTP server |
| Windows 11 24H2 | Workstation | User workstation |

### Network Appliances

| Appliance | Version | Access Method | Notes |
|-----------|---------|---------------|-------|
| VyOS | 1.4.x | SSH, Console | Router |
| Palo Alto | Various | Web GUI, SSH | Firewall (user-provided image) |
| Cisco FTD | 7.2.x | Web GUI | Firewall (user-provided image) |

### Default Credentials (Competition)

| System | Username | Password |
|--------|----------|----------|
| Linux servers | sysadmin | changeme |
| Windows servers | administrator | !Password123 |
| Palo Alto | admin | Changeme123 |
| Cisco FTD | admin | !Changeme123 |
| VyOS | vyos | changeme |

---

## Appendix A: Quick Reference Commands

### OS Detection

```bash
# Linux
cat /etc/os-release

# Windows PowerShell
Get-CimInstance Win32_OperatingSystem | Select Caption, Version
```

### Package Management

```bash
# Debian/Ubuntu
apt update && apt install -y <package>

# RHEL/Fedora
dnf install -y <package>

# Alpine
apk add <package>
```

### Service Management

```bash
# systemd (most Linux)
systemctl enable --now <service>
systemctl status <service>

# Windows
Get-Service <service>
Start-Service <service>
Set-Service <service> -StartupType Automatic
```

### Firewall

```bash
# iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload

# Windows
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Port 22 -Protocol TCP -Action Allow
```

---

## Appendix B: Competition Services Reference

### Scored Services (MWCCDC)

| Service | Port | Protocol | Validation |
|---------|------|----------|------------|
| HTTP | 80 | TCP | Content check |
| HTTPS | 443 | TCP | SSL + content check |
| SMTP | 25 | TCP | Send/receive email |
| POP3 | 110 | TCP | Email retrieval |
| DNS | 53 | UDP/TCP | Query resolution |
| FTP | 21 | TCP | File transfer |
| AD/LDAP | 389 | TCP | Authentication |

### Service Availability Tips

- Don't break services while hardening
- Test services after each change
- Document service dependencies
- Have rollback plans ready

---

*End of CLAUDE.md - CCDC Development Toolkit Guidelines*
