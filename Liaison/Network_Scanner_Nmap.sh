#!/bin/bash

# Nmap Network Scanner

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

LOG_DIR="/var/log/nmap_logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_DIR}/nmap_scan_${TIMESTAMP}.log"; exit 1; }

progress_bar() {
    local pid=$1 delay=0.1 spinstr='|/-\' i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r${YELLOW}[%c] Scanning...${NC}" "${spinstr:$i%4:1}"
        sleep $delay
        ((i++))
    done
    printf "\r${GREEN}Scan complete.${NC}\n"
}

trap 'log_info "Interrupted. Logs in $LOG_DIR."; exit 0' INT

[[ $EUID -ne 0 ]] && log_warn "Non-root: Limited scans (use sudo for SYN/OS)."

command -v nmap &>/dev/null || {
    log_info "Installing nmap..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq >/dev/null 2>&1 && apt-get install -y nmap &>>"${LOG_DIR}/install.log"
    elif command -v dnf &>/dev/null; then
        dnf install -y nmap &>>"${LOG_DIR}/install.log"
    elif command -v yum &>/dev/null; then
        yum install -y nmap &>>"${LOG_DIR}/install.log"
    else
        log_error "Install nmap manually."
    fi
}

echo -e "${GREEN}"
cat << 'EOF'
 __  __        _   _ __  __    _    ____    _   _   _ _ _ 
|  \/  | ___  | \ | |  \/  |  / \  |  _ \  | | | | | | | |
| |\/| |/ _ \ |  \| | |\/| | / _ \ | |_) | | | | | | | | |
| |  | |  __/ | |\  | |  | |/ ___ \|  __/  | |_| | |_|_|_|
|_|  |_|\___| |_| \_|_|  |_/_/   \_\_|      \___/  (_|_|_)
EOF
echo -e "${NC}"
echo -e "${YELLOW}Network Scanner${NC}"

get_target() {
    local default="192.168.1.0/24"
    read -p "Target (default $default): " target
    target=${target:-$default}
    [[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$ ]] || log_warn "Proceeding with '$target'."
    echo "$target"
}

run_nmap() {
    local cmd="$1" desc="$2" log_suffix="${3:-general}" log_file="${LOG_DIR}/nmap_${log_suffix}_${TIMESTAMP}.log"
    log_info "Running: $cmd ($desc)"
    echo "Command: $cmd" >> "$log_file"
    { nmap "$cmd" -oN "$log_file" 2>&1 | tee -a "$log_file"; } &
    progress_bar $!
    wait $!
    [[ -f $log_file && $(grep -c "Nmap done" "$log_file") -gt 0 ]] && {
        log_info "Results: $log_file"
        echo -e "\n${GREEN}Summary:${NC}"
        grep -E "(Nmap scan report|open)" "$log_file" | head -10
    } || log_warn "Check $log_file."
}

while true; do
    echo -e "\n${YELLOW}Menu:${NC}"
    echo "1) Host discovery (-sn)"
    echo "2) Port scan (-p-)"
    echo "3) Service version (-sV)"
    echo "4) OS detection (-O)"
    echo "5) Vuln scan (--script vuln)"
    echo "6) Aggressive (-A)"
    echo "7) Custom"
    echo "0) Exit"
    read -p "Choice: " choice
    case $choice in
        0) break ;;
        1|2|3|4|5|6)
            target=$(get_target)
            case $choice in
                1) cmd="-sn"; desc="Host discovery" ;;
                2) read -p "Timing (T4): " timing; timing=${timing:-T4}; cmd="-p- -T$timing"; desc="Port scan" ;;
                3) read -p "Ports: " ports; cmd="-sV ${ports:+-p $ports}"; desc="Service version" ;;
                4) cmd="-O"; desc="OS detection" ;;
                5) cmd="--script vuln"; desc="Vuln scan" ;;
                6) cmd="-A"; desc="Aggressive scan" ;;
            esac
            run_nmap "$cmd $target" "$desc" "${choice}"
            ;;
        7) read -p "Nmap cmd: " custom; run_nmap "$custom" "Custom" "custom" ;;
        *) log_warn "Invalid." ;;
    esac
    read -p "Another? (y/n): " yn; [[ $yn =~ ^[Nn]$ ]] && break
done

log_info "Logs in $LOG_DIR."
