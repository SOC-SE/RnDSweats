#!/bin/bash

################################################################################
# Security Scanner Setup and Execution Script
# Made with Claude AI + Cheat Sheet (makes it easier to go through cheat sheet rk commands rather than enter them manually)
#
# Purpose:
#   This script provides a comprehensive security scanning toolkit for Linux
#   systems. It installs and manages three key security tools (rkhunter, 
#   chkrootkit, and ClamAV) and provides various system integrity checks.
#
# Features:
#   - Automated installation of security tools across multiple distributions
#   - ClamAV antivirus scanning with logging capabilities
#   - chkrootkit rootkit detection with logging
#   - Advanced security checks including:
#     * Process integrity verification
#     * Kernel module analysis
#     * Binary integrity checks
#     * /proc and /dev anomaly detection
#     * Network anomaly detection
#     * File hiding technique detection
#
# Supported Distributions:
#   - Ubuntu (Desktop/Server 24.04.3 and others)
#   - Fedora (42 and others)
#   - Oracle Linux (9.2 and others)
#   - Debian-based systems
#   - RHEL-based systems
#
# Requirements:
#   - Must be run as root
#   - Internet connection for package installation
#
# Usage:
#   sudo ./security_scanner_setup.sh or sudo bash security_scanner_setup.sh
#
################################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log directory
LOG_DIR="/var/log/syst"

# Check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Create log directory if it doesn't exist
create_log_dir() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
        echo -e "${GREEN}Created log directory: $LOG_DIR${NC}"
    fi
}

# Detect distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi
}

# Install packages based on distribution
install_tools() {
    echo -e "${BLUE}Installing rkhunter, chkrootkit, and clamav...${NC}"
    
    detect_distro
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y rkhunter chkrootkit clamav clamav-daemon
            freshclam
            ;;
        fedora)
            dnf install -y rkhunter chkrootkit clamav clamd clamav-update
            freshclam
            ;;
        ol|rhel|centos|rocky|almalinux)
            # Enable EPEL for some packages
            if ! rpm -q epel-release &>/dev/null; then
                yum install -y epel-release
            fi
            yum install -y rkhunter chkrootkit clamav clamd clamav-update
            freshclam
            ;;
        opensuse*|sles)
            zypper install -y rkhunter chkrootkit clamav
            freshclam
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm rkhunter chkrootkit clamav
            freshclam
            ;;
        *)
            echo -e "${RED}Unsupported distribution: $DISTRO${NC}"
            echo -e "${YELLOW}Please install rkhunter, chkrootkit, and clamav manually${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}Installation completed successfully!${NC}"
    read -p "Press Enter to continue..."
}

# ClamAV scan
clamav_scan() {
    echo -e "${BLUE}ClamAV Scan${NC}"
    read -p "Enter directory to scan (e.g., /home): " scan_dir
    
    if [[ ! -d "$scan_dir" ]]; then
        echo -e "${RED}Directory does not exist: $scan_dir${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    log_file="$LOG_DIR/clamav_scan_$timestamp.log"
    
    echo -e "${YELLOW}Starting ClamAV scan on $scan_dir...${NC}"
    echo -e "${YELLOW}This may take a while depending on the size of the directory.${NC}"
    echo -e "${YELLOW}Log will be saved to: $log_file${NC}"
    
    clamscan -r "$scan_dir" | tee "$log_file"
    
    echo -e "${GREEN}Scan completed. Log saved to: $log_file${NC}"
    read -p "Press Enter to continue..."
}

# chkrootkit scan
chkrootkit_scan() {
    echo -e "${BLUE}chkrootkit Scan${NC}"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    log_file="$LOG_DIR/chkrootkit_$timestamp.log"
    
    echo -e "${YELLOW}Starting chkrootkit scan...${NC}"
    echo -e "${YELLOW}Log will be saved to: $log_file${NC}"
    
    chkrootkit | tee "$log_file"
    
    echo -e "${GREEN}Scan completed. Log saved to: $log_file${NC}"
    read -p "Press Enter to continue..."
}

# Process Integrity submenu
process_integrity_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Process Integrity ===${NC}"
        echo "1. DELETED executables (!)"
        echo "2. Processes from /tmp"
        echo "3. Hidden process check"
        echo "4. Process masquerading"
        echo "5. Process exe vs cmdline"
        echo "6. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: DELETED executables check${NC}"
                ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Running: Processes from /tmp check${NC}"
                ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp'
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: Hidden process check${NC}"
                echo -e "${YELLOW}Warning: This check may be resource-intensive${NC}"
                diff <(ps aux | awk '{print $2}' | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n)
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Process masquerading check${NC}"
                ps aux | grep -E '\[.*\]\$' | grep -v '\[kworker\]|\[rcu\]|\[migration'
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${YELLOW}Running: Process exe vs cmdline check${NC}"
                for p in /proc/[0-9]*/exe; do echo "$p -> $(readlink $p 2>/dev/null)"; done | head -30
                read -p "Press Enter to continue..."
                ;;
            6)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Kernel Module Analysis submenu
kernel_module_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Kernel Module Analysis ===${NC}"
        echo "1. Loaded modules"
        echo "2. Module count comparison"
        echo "3. Kernel tainted status"
        echo "4. Module details"
        echo "5. Recently modified modules"
        echo "6. Unsigned modules"
        echo "7. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: Loaded modules${NC}"
                lsmod
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Running: Module count comparison${NC}"
                echo "lsmod: $(lsmod | wc -l)" && echo "/proc/modules: $(cat /proc/modules | wc -l)"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: Kernel tainted status${NC}"
                cat /proc/sys/kernel/tainted
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Module details${NC}"
                read -p "Enter module name: " module_name
                if [[ -n "$module_name" ]]; then
                    modinfo "$module_name"
                else
                    echo -e "${RED}No module name provided${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${YELLOW}Running: Recently modified modules${NC}"
                find /lib/modules/$(uname -r) -name "*.ko" -mtime -30 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            6)
                echo -e "${YELLOW}Running: Unsigned modules${NC}"
                for m in $(lsmod | awk 'NR>1 {print $1}'); do modinfo $m 2>/dev/null | grep -q "sig_" || echo "Unsigned: $m"; done
                read -p "Press Enter to continue..."
                ;;
            7)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Binary Integrity submenu
binary_integrity_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Binary Integrity ===${NC}"
        echo "1. Verify Debian packages"
        echo "2. Verify RPM packages"
        echo "3. Critical binary hashes"
        echo "4. Compare to package"
        echo "5. Strings in suspect binary"
        echo "6. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: Verify Debian packages${NC}"
                if command -v debsums &>/dev/null; then
                    debsums -c 2>/dev/null | head -30
                else
                    echo -e "${RED}debsums not installed${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Running: Verify RPM packages${NC}"
                if command -v rpm &>/dev/null; then
                    rpm -Va 2>/dev/null | head -30
                else
                    echo -e "${RED}rpm not available on this system${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: Critical binary hashes${NC}"
                sha256sum /bin/ls /bin/ps /bin/ss /usr/bin/ssh /usr/sbin/sshd
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Compare to package${NC}"
                if command -v dpkg &>/dev/null; then
                    dpkg -V coreutils 2>/dev/null; rpm -V coreutils 2>/dev/null
                elif command -v rpm &>/dev/null; then
                    rpm -V coreutils 2>/dev/null
                else
                    echo -e "${RED}Neither dpkg nor rpm available${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${YELLOW}Running: Strings in suspect binary${NC}"
                read -p "Enter path to binary (e.g., /bin/ls): " binary_path
                if [[ -f "$binary_path" ]]; then
                    strings "$binary_path" | grep -iE 'shell|exec|socket|/bin/sh'
                else
                    echo -e "${RED}Binary not found: $binary_path${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# /proc & /dev Anomalies submenu
proc_dev_anomalies_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== /proc & /dev Anomalies ===${NC}"
        echo "1. Hidden /proc entries"
        echo "2. /dev hidden files"
        echo "3. /dev/shm contents"
        echo "4. Unusual char devices"
        echo "5. Recently modified /dev"
        echo "6. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: Hidden /proc entries${NC}"
                ls /proc | grep -v -E '^[0-9]+$|^[a-z]'
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Running: /dev hidden files${NC}"
                find /dev -type f 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: /dev/shm contents${NC}"
                ls -la /dev/shm/
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Unusual char devices${NC}"
                ls -la /dev | grep "^c" | grep -v -E 'tty|pts|null|zero|random'
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${YELLOW}Running: Recently modified /dev${NC}"
                find /dev -mtime -7 -type f 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            6)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Network Anomalies submenu
network_anomalies_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Network Anomalies ===${NC}"
        echo "1. Promiscuous mode (sniffing)"
        echo "2. Raw sockets"
        echo "3. Unusual outbound"
        echo "4. Packet capture processes"
        echo "5. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: Promiscuous mode check${NC}"
                ip link | grep PROMISC
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Running: Raw sockets check${NC}"
                cat /proc/net/raw 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: Unusual outbound connections${NC}"
                ss -tnp | grep -v -E ':22|:80|:443|:53'
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Packet capture processes${NC}"
                ps aux | grep -iE 'tcpdump|wireshark|tshark'
                read -p "Press Enter to continue..."
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# File Hiding Techniques submenu
file_hiding_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== File Hiding Techniques ===${NC}"
        echo "1. Immutable files scan"
        echo "2. Check specific files"
        echo "3. Files with no owner"
        echo "4. Hidden dotfiles (unusual)"
        echo "5. Dotfiles in root dirs"
        echo "6. Extended attributes"
        echo "7. Back to previous menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}Running: Immutable files scan${NC}"
                echo -e "${YELLOW}Warning: This check may be resource-intensive${NC}"
                lsattr -R / 2>/dev/null | grep 'i' | less
                ;;
            2)
                echo -e "${YELLOW}Running: Check specific files${NC}"
                lsattr /etc/ld.so.preload /bin/ls /bin/login /bin/ps 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Running: Files with no owner${NC}"
                echo -e "${YELLOW}Warning: This check may be resource-intensive${NC}"
                find / -nouser -o -nogroup 2>/dev/null | head -20
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "${YELLOW}Running: Hidden dotfiles (unusual)${NC}"
                find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${YELLOW}Running: Dotfiles in root dirs${NC}"
                find / -maxdepth 2 -name ".*" -type f 2>/dev/null | head -30
                read -p "Press Enter to continue..."
                ;;
            6)
                echo -e "${YELLOW}Running: Extended attributes${NC}"
                getfattr -d /usr/bin/* 2>/dev/null | head -20
                read -p "Press Enter to continue..."
                ;;
            7)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Other security checks menu
other_checks_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== Other Security Checks ===${NC}"
        echo "1. Process Integrity"
        echo "2. Kernel Module Analysis"
        echo "3. Binary Integrity"
        echo "4. /proc & /dev Anomalies"
        echo "5. Network Anomalies"
        echo "6. File Hiding Techniques"
        echo "7. Back to main menu"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1) process_integrity_menu ;;
            2) kernel_module_menu ;;
            3) binary_integrity_menu ;;
            4) proc_dev_anomalies_menu ;;
            5) network_anomalies_menu ;;
            6) file_hiding_menu ;;
            7) return ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main menu
main_menu() {
    while true; do
        clear
        echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║    Security Scanner Setup Script      ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
        echo
        echo "1. Install rkhunter, chkrootkit, and clamav"
        echo "2. ClamAV scan with a log"
        echo "3. chkrootkit with a log"
        echo "4. Other security checks"
        echo "5. Exit"
        echo
        read -p "Select an option: " choice
        
        case $choice in
            1) install_tools ;;
            2) clamav_scan ;;
            3) chkrootkit_scan ;;
            4) other_checks_menu ;;
            5)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main execution
check_root
create_log_dir
main_menu
