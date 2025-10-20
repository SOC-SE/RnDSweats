#!/bin/bash

# =====================================================================
# Script: Network_Scanner_Nmap.sh
# Description: A user-friendly NMAP-based Bash script for network scanning, 
# focusing on reconnaissance, host discovery, and vulnerability assessment 
# suitable for cybersecurity competitions like CCDC (Collegiate Cyber Defense Competition).
# It provides an interactive menu, automatic NMAP installation, colored output,
# progress indicators, and timestamped logging for ease of use in threat hunting.
#
# Version: 1.0
#
# Author: Autonomous Coding Agent
#
# Usage: 
#   Run as: bash Network_Scanner_Nmap.sh (non-root for basic scans)
#           or sudo bash Network_Scanner_Nmap.sh (for advanced features like OS detection)
#   - Follow on-screen prompts to select scan types (1-10).
#   - Enter targets (IP, range e.g., 192.168.1.0/24, or hostname).
#   - Outputs saved to /var/log/nmap_logs/ for full details; summaries shown on console.
#
# Dependencies:
#   - Bash 4.0+
#   - nmap (auto-installed if missing via apt/dnf/yum)
#   - sudo (for installation and privileged scans)
#   - Supported OS: Debian/Ubuntu, Fedora, CentOS/RHEL
#
# Features:
#   - Menu-driven with 10 scan options.
#   - Error handling, input validation, Ctrl+C trap.
#   - Colored console output (green/info, yellow/warn, red/error).
#   - Progress spinner for long scans.
#
# Notes:
#   - Requires root for SYN scans, OS detection (-O), aggressive scans (-A).
#   - Logs all activities; review for compliance in competitions.
#
# Disclaimer: 
#   This script is for educational and authorized use only. Network scanning 
#   without permission is illegal. Ensure you have explicit consent before scanning.
#   Not responsible for misuse or damages.
#
# License: MIT License - Free to use, modify, and distribute.
# =====================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# TeamPack Compliance Notice
# Network scanning and vulnerability checks must only be performed on systems you
# are authorized to scan (your team/lab VMs). Scanning outside that scope may
# violate competition rules and local laws. You must type YES to confirm.
# ------------------------------------------------------------------------------
teampack_confirm() {
    echo ""
    echo "WARNING: Only scan systems you are authorized to test."
    read -p "I confirm I will only scan my team/lab systems (type YES to continue): " _confirm
    if [[ "$_confirm" != "YES" ]]; then
        echo "Confirmation not received. Exiting."
        exit 1
    fi
}

# Run TeamPack confirmation
teampack_confirm

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'  # No Color

# Log directory
LOG_DIR="/var/log/nmap_logs"
mkdir -p "$LOG_DIR"

# Timestamp for logs
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ASCII Banner for NMAP
echo -e "${GREEN}"
cat << 'EOF'
 __  __        _   _ __  __    _    ____    _   _   _ _ _ 
|  \/  | ___  | \ | |  \/  |  / \  |  _ \  | | | | | | | |
| |\/| |/ _ \ |  \| | |\/| | / _ \ | |_) | | | | | | | | |
| |  | |  __/ | |\  | |  | |/ ___ \|  __/  | |_| | |_|_|_|
|_|  |_|\___| |_| \_|_|  |_/_/   \_\_|      \___/  (_|_|_)

EOF
echo -e "${NC}"

# Title
echo -e "${YELLOW}Network Scanner with Nmap - For CCDC Threat Hunting${NC}"
echo "=================================================================================="

# Helper Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"
    exit 1
}

# Progress bar function (simple spinner for scans)
progress_bar() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r${YELLOW}[%c] Scanning...${NC}" "${spinstr:$i:1}"
        sleep $delay
    done
    printf "\r${GREEN}Scan completed.${NC}\n"
}

# Handle Ctrl+C gracefully
trap 'log_info "Scan interrupted by user. Logs saved in $LOG_DIR."; exit 0' INT

# Check for root privileges (NMAP often requires root for advanced scans)
if [[ $EUID -ne 0 ]]; then
    log_warn "Script is not running as root. Some scans (e.g., SYN, OS detection) may require elevated privileges. Use sudo if needed."
fi

# Check and install NMAP if not present
if ! command -v nmap &> /dev/null; then
    log_info "NMAP not found. Attempting automatic installation..."
    if [[ -f /etc/debian_version ]] || [[ -f /etc/os-release && $(grep '^ID=' /etc/os-release | cut -d= -f2) == *"ubuntu"* || $(grep '^ID=' /etc/os-release | cut -d= -f2) == *"debian"* ]]; then
        # Debian/Ubuntu
        if sudo command -v apt &> /dev/null; then
            sudo apt update &>/dev/null && sudo apt install -y nmap &>>"${LOG_DIR}/install.log"
            log_info "NMAP installed via apt."
        else
            log_error "apt not available for installation."
        fi
    elif [[ -f /etc/redhat-release ]] || [[ -f /etc/os-release && $(grep '^ID=' /etc/os-release | cut -d= -f2) == *"fedora"* ]]; then
        # Fedora
        if sudo command -v dnf &> /dev/null; then
            sudo dnf install -y nmap &>>"${LOG_DIR}/install.log"
            log_info "NMAP installed via dnf."
        else
            log_error "dnf not available."
        fi
    elif [[ -f /etc/redhat-release ]] || [[ -f /etc/os-release && $(grep '^ID=' /etc/os-release | cut -d= -f2) == *"centos"* ]]; then
        # CentOS
        if sudo command -v yum &> /dev/null; then
            sudo yum install -y nmap &>>"${LOG_DIR}/install.log"
            log_info "NMAP installed via yum."
        else
            log_error "yum not available."
        fi
    else
        log_error "Unsupported OS for automatic NMAP installation. Please install manually."
    fi
else
    log_info "NMAP is already installed."
fi

# Function to get and validate target
get_target() {
    local default="192.168.1.0/24"
    read -p "Enter target IP, range, or hostname (default: $default): " target
    target=${target:-$default}
    
    # Basic validation (IP, range, or hostname)
    if [[ ! $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && [[ ! $target =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        log_warn "Target '$target' may not be a valid IP/range or hostname. Proceeding anyway."
    fi
    echo "$target"
}

# Function to run NMAP command with logging and progress
run_nmap() {
    local cmd="$1"
    local desc="$2"
    local log_suffix="${3:-general}"
    local log_file="${LOG_DIR}/nmap_${log_suffix}_${TIMESTAMP}.log"
    
    log_info "Running: $cmd"
    log_info "Description: $desc"
    echo "Command: $cmd" >> "$log_file"
    
    { eval "$cmd" -oN "$log_file" 2>&1 | tee -a "$log_file"; } &
    local pid=$!
    progress_bar $pid
    wait $pid
    
    if [[ -f "$log_file" && $(grep -c "Nmap done" "$log_file" || true) -gt 0 ]]; then
        log_info "Full results saved to: $log_file"
        # Display summary: extract key lines
        echo -e "\n${GREEN}=== Scan Summary ===${NC}"
        grep -E "(Nmap scan report|open|Discovered open port)" "$log_file" | head -10 || echo "No key findings to display."
        echo -e "${GREEN}====================${NC}\n"
    else
        log_warn "Scan may have failed. Check $log_file for details."
    fi
}

# Main menu loop
while true; do
    echo -e "\n${YELLOW}=== NMAP Scan Menu ===${NC}"
    echo "1) List available scan types (NMAP help)"
    echo "2) Basic host discovery (-sn)"
    echo "3) Port scan (all ports, -p-)"
    echo "4) Service version detection (-sV)"
    echo "5) OS detection (-O)"
    echo "6) Vulnerability scan (--script vuln)"
    echo "7) Aggressive scan (-A)"
    echo "8) Scan and save to file (-oN)"
    echo "9) Custom script scan (--script <name>)"
    echo "10) Custom NMAP command"
    echo "0) Exit"
    read -p "Select option (0-10): " choice
    
    case $choice in
        0)
            break
            ;;
        1)
            log_info "Displaying NMAP scan types help."
            nmap -h | head -50
            ;;
        2)
            local target=$(get_target)
            local cmd="nmap -sn $target"
            local desc="Basic host discovery"
            run_nmap "$cmd" "$desc" "host_discovery"
            ;;
        3)
            local target=$(get_target)
            read -p "Enter timing template (default: T4) [T0-T5]: " timing
            timing=${timing:-T4}
            local cmd="nmap -p- -T$timing $target"
            local desc="Port scan for all ports"
            run_nmap "$cmd" "$desc" "port_scan"
            ;;
        4)
            local target=$(get_target)
            read -p "Specify ports (default: top 1000) [e.g., 1-1024 or default]: " ports
            ports=${ports:-}
            local cmd="nmap -sV ${ports:+-p $ports} $target"
            local desc="Service version detection"
            run_nmap "$cmd" "$desc" "service_detection"
            ;;
        5)
            local target=$(get_target)
            if [[ $EUID -ne 0 ]]; then
                log_warn "OS detection requires root privileges for best results."
            fi
            local cmd="nmap -O $target"
            local desc="OS detection"
            run_nmap "$cmd" "$desc" "os_detection"
            ;;
        6)
            local target=$(get_target)
            local cmd="nmap --script vuln $target"
            local desc="Vulnerability scanning"
            run_nmap "$cmd" "$desc" "vuln_scan"
            ;;
        7)
            local target=$(get_target)
            if [[ $EUID -ne 0 ]]; then
                log_warn "Aggressive scan requires root for full functionality."
            fi
            local cmd="nmap -A $target"
            local desc="Aggressive scan (OS, version, script, traceroute)"
            run_nmap "$cmd" "$desc" "aggressive"
            ;;
        8)
            local target=$(get_target)
            local custom_log="custom_$(date +%s).nmap"
            read -p "Output filename (default: $custom_log): " out_file
            out_file=${out_file:-$custom_log}
            local full_path="${LOG_DIR}/$out_file"
            local cmd="nmap $target -oN \"$full_path\""
            local desc="Scan and save to file"
            run_nmap "$cmd" "$desc" "saved_scan"
            ;;
        9)
            local target=$(get_target)
            read -p "Enter NSE script name (e.g., http-vuln-cve2017-5638): " script
            if [[ -z $script ]]; then
                log_error "Script name required."
            fi
            local cmd="nmap --script $script $target"
            local desc="Custom NSE script scan: $script"
            run_nmap "$cmd" "$desc" "script_scan_${script//[^a-zA-Z0-9]/_}"
            ;;
        10)
            read -p "Enter full NMAP command (include target, e.g., 'nmap -sV target.com'): " custom_cmd
            if [[ -z $custom_cmd ]]; then
                log_warn "No command provided. Skipping."
                continue
            fi
            local desc="Custom command"
            run_nmap "$custom_cmd" "$desc" "custom"
            ;;
        *)
            log_warn "Invalid option. Please select 0-10."
            continue
            ;;
    esac
    
    # Ask for another scan
    read -p "Run another scan? (y/n): " yn
    if [[ ! $yn =~ ^[Yy]$ ]]; then
        break
    fi
done

# End message
log_info "Script completed. All logs are saved in $LOG_DIR. Review them for detailed results."
echo -e "${GREEN}Happy threat hunting!${NC}"
