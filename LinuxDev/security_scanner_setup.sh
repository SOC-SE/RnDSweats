#!/bin/bash

################################################################################
# ClamAV and RKhunter Installation & Management Script
################################################################################
# Made with Claude AI
# Description:
#   This script installs and configures ClamAV and RKhunter on major Linux
#   distributions. It provides easy-to-use options for scanning systems.
#
# Usage:
#   Installation:
#     sudo bash security_scanner_setup.sh --install
#
#   Scanning operations (not necessary, can still do regular scans with the tools themselves): 
#     sudo bash security_scanner_setup.sh --clamscan-file <path>
#     sudo bash security_scanner_setup.sh --clamscan-file <path> --no-log
#     sudo bash security_scanner_setup.sh --clamscan-system
#     sudo bash security_scanner_setup.sh --clamscan-system --no-log
#     sudo bash security_scanner_setup.sh --rkhunter-scan
#     sudo bash security_scanner_setup.sh --rkhunter-scan --no-log
#     sudo bash security_scanner_setup.sh --rkhunter-baseline
#
#   Help:
#     sudo bash security_scanner_setup.sh --help
#
# Important Notes:
#   - Run as root/sudo (script will check)
#   - For RKhunter: DO NOT run baseline until you're confident system is clean
#   - Signature databases are updated during installation
#   - Scan results saved to /var/log/security-scans/ (unless --no-log is used)
#
# Supported Distributions:
#   Ubuntu/Debian, Fedora, RHEL/CentOS/Rocky/Alma, Arch, openSUSE, Kali
#
################################################################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log directory
LOG_DIR="/var/log/security-scans"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "$1"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_help() {
    echo -e "${CYAN}${BOLD}ClamAV & RKhunter Security Scanner Script${NC}"
    echo ""
    echo -e "${BOLD}INSTALLATION:${NC}"
    echo "  sudo bash $0 --install"
    echo "    Install ClamAV and RKhunter with updated signatures"
    echo ""
    echo -e "${BOLD}SCANNING OPTIONS:${NC}"
    echo "  sudo bash $0 --clamscan-file <path>"
    echo "    Scan a specific file or directory with ClamAV"
    echo "    Example: sudo bash $0 --clamscan-file /home"
    echo ""
    echo "  sudo bash $0 --clamscan-file <path> --no-log"
    echo "    Scan without creating a log file (display summary only)"
    echo ""
    echo "  sudo bash $0 --clamscan-system"
    echo "    Scan the entire system with ClamAV (may take a long time)"
    echo ""
    echo "  sudo bash $0 --clamscan-system --no-log"
    echo "    Scan entire system without creating a log file"
    echo ""
    echo "  sudo bash $0 --rkhunter-scan"
    echo "    Run RKhunter security scan for rootkits"
    echo ""
    echo "  sudo bash $0 --rkhunter-scan --no-log"
    echo "    Run RKhunter scan without creating a log file"
    echo ""
    echo "  sudo bash $0 --rkhunter-baseline"
    echo "    Establish RKhunter baseline (only after verifying system is clean!)"
    echo ""
    echo -e "${BOLD}OTHER OPTIONS:${NC}"
    echo "  sudo bash $0 --help"
    echo "    Display this help message"
    echo ""
    echo -e "${BOLD}NOTES:${NC}"
    echo "  - All operations require root/sudo privileges"
    echo "  - Scan logs are saved to: ${LOG_DIR}"
    echo "  - Use --no-log flag to avoid creating log files (saves storage)"
    echo -e "  - ${YELLOW}WARNING: Only run --rkhunter-baseline when system is verified clean!${NC}"
    echo ""
}

################################################################################
# Root Check
################################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        echo -e "${YELLOW}Usage: sudo $0 [option]${NC}"
        echo -e "${YELLOW}Use --help for more information${NC}"
        exit 1
    fi
}

################################################################################
# Distribution Detection
################################################################################

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        print_error "Unable to detect Linux distribution"
        exit 1
    fi
    
    print_info "Detected distribution: $DISTRO"
}

################################################################################
# Package Manager Functions
################################################################################

update_system() {
    print_info "Updating package lists..."
    case $DISTRO in
        ubuntu|debian|kali)
            apt-get update -qq
            ;;
        fedora)
            dnf check-update -q || true
            ;;
        rhel|centos|rocky|almalinux)
            yum check-update -q || true
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm
            ;;
        opensuse*|sles)
            zypper refresh -q
            ;;
        *)
            print_warning "Unknown distribution, skipping update"
            ;;
    esac
}

install_package() {
    local package=$1
    print_info "Installing $package..."
    
    case $DISTRO in
        ubuntu|debian|kali)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $package
            ;;
        fedora)
            dnf install -y -q $package
            ;;
        rhel|centos|rocky|almalinux)
            yum install -y -q $package
            ;;
        arch|manjaro)
            pacman -S --noconfirm --quiet $package
            ;;
        opensuse*|sles)
            zypper install -y $package
            ;;
        *)
            print_error "Unsupported distribution for automatic installation"
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        print_success "$package installed successfully"
        return 0
    else
        print_error "Failed to install $package"
        return 1
    fi
}

################################################################################
# ClamAV Installation and Configuration
################################################################################

install_clamav() {
    print_header "ClamAV Installation"
    
    # Check if already installed
    if command -v clamscan &> /dev/null; then
        print_warning "ClamAV is already installed"
        read -p "Do you want to reinstall/update? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Install ClamAV based on distribution
    case $DISTRO in
        ubuntu|debian|kali)
            install_package "clamav clamav-freshclam"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_package "clamav clamav-update"
            # Enable EPEL if needed on RHEL-based
            if [[ $DISTRO == "rhel" ]] || [[ $DISTRO == "centos" ]]; then
                install_package "epel-release" 2>/dev/null || true
            fi
            ;;
        arch|manjaro)
            install_package "clamav"
            ;;
        opensuse*|sles)
            install_package "clamav"
            ;;
        *)
            print_error "Unsupported distribution for ClamAV installation"
            return 1
            ;;
    esac
    
    # Stop freshclam service if running to update manually
    systemctl stop clamav-freshclam 2>/dev/null || service clamav-freshclam stop 2>/dev/null || true
    
    print_info "Updating ClamAV virus definitions (this may take a few minutes)..."
    freshclam --quiet 2>/dev/null || freshclam
    
    if [ $? -eq 0 ]; then
        print_success "ClamAV virus definitions updated successfully"
    else
        print_warning "ClamAV update completed with warnings (this is often normal)"
    fi
    
    print_success "ClamAV installation complete"
}

################################################################################
# RKhunter Installation and Configuration
################################################################################

install_rkhunter() {
    print_header "RKhunter Installation"
    
    # Check if already installed
    if command -v rkhunter &> /dev/null; then
        print_warning "RKhunter is already installed"
        read -p "Do you want to reinstall/update? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Install RKhunter based on distribution
    case $DISTRO in
        ubuntu|debian|kali)
            install_package "rkhunter"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_package "rkhunter"
            ;;
        arch|manjaro)
            install_package "rkhunter"
            ;;
        opensuse*|sles)
            install_package "rkhunter"
            ;;
        *)
            print_error "Unsupported distribution for RKhunter installation"
            return 1
            ;;
    esac
    
    print_info "Updating RKhunter data files..."
    rkhunter --update --quiet 2>/dev/null || rkhunter --update
    
    if [ $? -eq 0 ]; then
        print_success "RKhunter data files updated successfully"
    else
        print_warning "RKhunter update completed with warnings"
    fi
    
    # Display important warning about baseline
    echo ""
    print_warning "IMPORTANT: RKhunter Baseline Notice"
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  RKhunter requires a baseline of your system's binaries.      ║${NC}"
    echo -e "${YELLOW}║  DO NOT establish this baseline until you are CONFIDENT       ║${NC}"
    echo -e "${YELLOW}║  your system is clean and free from rootkits/malware.         ║${NC}"
    echo -e "${YELLOW}║                                                                ║${NC}"
    echo -e "${YELLOW}║  To establish baseline later, use:                            ║${NC}"
    echo -e "${YELLOW}║    ${CYAN}sudo bash $0 --rkhunter-baseline${YELLOW}                  ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_success "RKhunter installation complete"
}

################################################################################
# Scanning Functions
################################################################################

clamscan_file() {
    local TARGET="$1"
    local NO_LOG="$2"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOGFILE="$LOG_DIR/clamscan_${TIMESTAMP}.log"
    
    if [ -z "$TARGET" ]; then
        print_error "Please specify a file or directory to scan"
        echo -e "${CYAN}Usage: sudo bash $0 --clamscan-file <path> [--no-log]${NC}"
        exit 1
    fi
    
    if [ ! -e "$TARGET" ]; then
        print_error "Path does not exist: $TARGET"
        exit 1
    fi
    
    # Check if ClamAV is installed
    if ! command -v clamscan &> /dev/null; then
        print_error "ClamAV is not installed. Run with --install first."
        exit 1
    fi
    
    print_header "ClamAV File/Directory Scan"
    echo -e "${CYAN}Target: $TARGET${NC}"
    
    if [ "$NO_LOG" == "--no-log" ]; then
        echo -e "${YELLOW}Running without log file (summary only)${NC}"
        echo ""
        clamscan -r -i "$TARGET"
    else
        # Ensure log directory exists
        mkdir -p "$LOG_DIR"
        echo -e "${CYAN}Log file: $LOGFILE${NC}"
        echo ""
        clamscan -r -i --log="$LOGFILE" "$TARGET" 2>&1 | tee -a "$LOGFILE"
        echo ""
        if [ -f "$LOGFILE" ]; then
            print_success "Scan complete. Full log saved to: $LOGFILE"
        else
            print_warning "Scan complete but log file was not created at: $LOGFILE"
        fi
    fi
}

clamscan_system() {
    local NO_LOG="$1"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOGFILE="$LOG_DIR/clamscan_system_${TIMESTAMP}.log"
    
    # Check if ClamAV is installed
    if ! command -v clamscan &> /dev/null; then
        print_error "ClamAV is not installed. Run with --install first."
        exit 1
    fi
    
    print_header "ClamAV Full System Scan"
    print_warning "Full system scan may take a long time!"
    
    if [ "$NO_LOG" == "--no-log" ]; then
        echo -e "${YELLOW}Running without log file (summary only)${NC}"
        echo ""
        clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" /
    else
        # Ensure log directory exists
        mkdir -p "$LOG_DIR"
        echo -e "${CYAN}Log file: $LOGFILE${NC}"
        echo ""
        clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" \
            --log="$LOGFILE" / 2>&1 | tee -a "$LOGFILE"
        echo ""
        if [ -f "$LOGFILE" ]; then
            print_success "System scan complete. Full log saved to: $LOGFILE"
        else
            print_warning "Scan complete but log file was not created at: $LOGFILE"
        fi
    fi
}

rkhunter_scan() {
    local NO_LOG="$1"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOGFILE="$LOG_DIR/rkhunter_${TIMESTAMP}.log"
    
    # Check if RKhunter is installed
    if ! command -v rkhunter &> /dev/null; then
        print_error "RKhunter is not installed. Run with --install first."
        exit 1
    fi
    
    print_header "RKhunter Security Scan"
    
    # Check if baseline exists
    if [ ! -f /var/lib/rkhunter/db/rkhunter.dat ]; then
        print_warning "No RKhunter baseline found!"
        echo -e "${YELLOW}This is expected if you haven't run '--rkhunter-baseline' yet.${NC}"
        echo -e "${YELLOW}Results may show many warnings without a baseline.${NC}"
        echo ""
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
    
    if [ "$NO_LOG" == "--no-log" ]; then
        echo -e "${YELLOW}Running without log file (summary only)${NC}"
        echo ""
        rkhunter --check --skip-keypress --report-warnings-only
    else
        # Ensure log directory exists
        mkdir -p "$LOG_DIR"
        echo -e "${CYAN}Log file: $LOGFILE${NC}"
        echo ""
        rkhunter --check --skip-keypress --report-warnings-only --log "$LOGFILE" 2>&1 | tee -a "$LOGFILE"
        echo ""
        if [ -f "$LOGFILE" ]; then
            print_success "RKhunter scan complete. Full log saved to: $LOGFILE"
            echo -e "${CYAN}Review the log for any warnings or suspicious findings.${NC}"
        else
            print_warning "Scan complete but log file was not created at: $LOGFILE"
        fi
    fi
}

rkhunter_baseline() {
    # Check if RKhunter is installed
    if ! command -v rkhunter &> /dev/null; then
        print_error "RKhunter is not installed. Run with --install first."
        exit 1
    fi
    
    print_header "RKhunter Baseline Establishment"
    echo ""
    echo -e "${RED}WARNING: Only run this if you are CONFIDENT your system is clean!${NC}"
    echo ""
    echo -e "${CYAN}This will create a baseline of your system's binaries and files.${NC}"
    echo -e "${CYAN}Future scans will compare against this baseline.${NC}"
    echo ""
    echo -e "${YELLOW}Have you verified your system is free from malware/rootkits?${NC}"
    read -p "Are you sure you want to proceed? (yes/no): " -r
    echo

    if [[ ! $REPLY == "yes" ]]; then
        print_info "Baseline creation cancelled."
        exit 0
    fi

    echo ""
    print_info "Updating RKhunter data files..."
    rkhunter --update

    print_info "Creating system baseline..."
    rkhunter --propupd

    if [ $? -eq 0 ]; then
        echo ""
        print_success "RKhunter baseline established successfully!"
        echo -e "${CYAN}You can now run 'sudo bash $0 --rkhunter-scan' to check your system.${NC}"
    else
        echo ""
        print_error "Error establishing baseline"
        exit 1
    fi
}

################################################################################
# Main Installation Function
################################################################################

run_installation() {
    clear
    print_header "ClamAV & RKhunter Security Scanner Setup"
    
    # Detect distribution
    detect_distro
    
    # Update system
    update_system
    
    echo ""
    print_info "This script will install ClamAV and RKhunter"
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Installation cancelled"
        exit 0
    fi
    
    echo ""
    
    # Install ClamAV
    read -p "Install ClamAV? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_clamav
    fi
    
    echo ""
    
    # Install RKhunter
    read -p "Install RKhunter? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_rkhunter
    fi
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    # Final summary
    echo ""
    print_header "Installation Complete!"
    echo ""
    print_success "Available options:"
    echo -e "  ${CYAN}sudo bash $0 --clamscan-file <path>${NC}"
    echo -e "    Scan specific file or directory"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --clamscan-file <path> --no-log${NC}"
    echo -e "    Scan without creating a log file"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --clamscan-system${NC}"
    echo -e "    Scan entire system (takes time)"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --clamscan-system --no-log${NC}"
    echo -e "    Scan entire system without log file"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --rkhunter-scan${NC}"
    echo -e "    Run RKhunter security scan"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --rkhunter-scan --no-log${NC}"
    echo -e "    Run RKhunter scan without log file"
    echo ""
    echo -e "  ${CYAN}sudo bash $0 --rkhunter-baseline${NC}"
    echo -e "    Establish RKhunter baseline (when clean)"
    echo ""
    print_info "Scan logs are saved to: $LOG_DIR (unless --no-log is used)"
    echo ""
    print_warning "Remember: Establish RKhunter baseline only when system is verified clean!"
    echo ""
}

################################################################################
# Main Script Logic
################################################################################

# Check root privileges
check_root

# Parse command line arguments
case "${1}" in
    --install)
        run_installation
        ;;
    --clamscan-file)
        if [ "$3" == "--no-log" ]; then
            clamscan_file "$2" "--no-log"
        else
            clamscan_file "$2"
        fi
        ;;
    --clamscan-system)
        if [ "$2" == "--no-log" ]; then
            clamscan_system "--no-log"
        else
            clamscan_system
        fi
        ;;
    --rkhunter-scan)
        if [ "$2" == "--no-log" ]; then
            rkhunter_scan "--no-log"
        else
            rkhunter_scan
        fi
        ;;
    --rkhunter-baseline)
        rkhunter_baseline
        ;;
    --help|-h|"")
        show_help
        exit 0
        ;;
    *)
        print_error "Unknown option: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
