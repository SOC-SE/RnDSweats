#!/bin/bash
# Universal Ansible Installer for CCDC Competitions
# Enhanced detection based on package manager and service manager
# More robust for competitions where /etc/os-release might be tampered with

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
PACKAGE_MANAGER=""
SERVICE_MANAGER=""
DISTRO_FAMILY=""
PYTHON_CMD=""
DISTRO_NAME=""
DISTRO_VERSION=""
PLAYBOOK_DIR="/etc/auto"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

log_success() {
    echo -e "${CYAN}[SUCCESS]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Detect package manager (primary detection method)
detect_package_manager() {
    log_info "Detecting package manager..."
    
    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt"
        DISTRO_FAMILY="debian"
        log_debug "Found: apt-get (Debian/Ubuntu/Devuan family)"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
        DISTRO_FAMILY="rhel"
        log_debug "Found: dnf (Fedora/RHEL 8+/Rocky/Alma family)"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
        DISTRO_FAMILY="rhel"
        log_debug "Found: yum (RHEL/CentOS/Oracle Linux family)"
    elif command -v apk &> /dev/null; then
        PACKAGE_MANAGER="apk"
        DISTRO_FAMILY="alpine"
        log_debug "Found: apk (Alpine Linux family)"
    elif command -v pacman &> /dev/null; then
        PACKAGE_MANAGER="pacman"
        DISTRO_FAMILY="arch"
        log_debug "Found: pacman (Arch/Manjaro family)"
    elif command -v zypper &> /dev/null; then
        PACKAGE_MANAGER="zypper"
        DISTRO_FAMILY="suse"
        log_debug "Found: zypper (openSUSE/SLES family)"
    elif command -v emerge &> /dev/null; then
        PACKAGE_MANAGER="emerge"
        DISTRO_FAMILY="gentoo"
        log_debug "Found: emerge (Gentoo/Funtoo family)"
    elif command -v pkg &> /dev/null; then
        PACKAGE_MANAGER="pkg"
        DISTRO_FAMILY="bsd"
        log_debug "Found: pkg (FreeBSD family)"
    else
        log_warn "No recognized package manager found"
        PACKAGE_MANAGER="none"
        DISTRO_FAMILY="unknown"
    fi
    
    log_info "Package Manager: ${CYAN}$PACKAGE_MANAGER${NC}"
}

# Detect service/init manager (helps identify the system better)
detect_service_manager() {
    log_info "Detecting service/init manager..."
    
    # Check for systemd (most modern systems)
    if [ -d /run/systemd/system ] || command -v systemctl &> /dev/null; then
        SERVICE_MANAGER="systemd"
        log_debug "Found: systemd (most modern Linux distributions)"
    
    # Check for OpenRC (Alpine, Gentoo, some Devuan configurations)
    elif command -v rc-service &> /dev/null || [ -f /sbin/openrc-run ]; then
        SERVICE_MANAGER="openrc"
        log_debug "Found: OpenRC (Alpine/Gentoo/some Devuan)"
    
    # Check for SysVinit (older systems, Devuan Chimaera default)
    elif [ -f /sbin/init ] && [ ! -L /sbin/init ] && strings /sbin/init 2>/dev/null | grep -q "sysvinit"; then
        SERVICE_MANAGER="sysvinit"
        log_debug "Found: SysVinit (older systems, Devuan)"
    
    # Check for Upstart (some older Ubuntu)
    elif [ -f /sbin/init ] && /sbin/init --version 2>&1 | grep -q "upstart"; then
        SERVICE_MANAGER="upstart"
        log_debug "Found: Upstart (older Ubuntu)"
    
    # Check for runit (Void Linux, some custom setups)
    elif command -v sv &> /dev/null || [ -d /etc/runit ]; then
        SERVICE_MANAGER="runit"
        log_debug "Found: runit (Void Linux)"
    
    # Check for s6 (some minimal/embedded systems)
    elif command -v s6-svc &> /dev/null || [ -d /etc/s6 ]; then
        SERVICE_MANAGER="s6"
        log_debug "Found: s6 (embedded/minimal systems)"
    
    # Fallback: check for init.d directory (generic SysV-style)
    elif [ -d /etc/init.d ] && [ ! -d /run/systemd/system ]; then
        SERVICE_MANAGER="sysvinit"
        log_debug "Found: SysVinit-style (fallback detection via /etc/init.d)"
    
    else
        SERVICE_MANAGER="unknown"
        log_warn "Could not reliably detect service manager"
    fi
    
    log_info "Service Manager: ${CYAN}$SERVICE_MANAGER${NC}"
}

# Detect Python (needed for Ansible)
detect_python() {
    log_info "Detecting Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        log_debug "Found: python3 (version $PYTHON_VERSION)"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
        log_debug "Found: python (version $PYTHON_VERSION)"
    else
        log_warn "Python not found - will be installed as dependency"
        PYTHON_CMD=""
    fi
}

# Get distro name and version (secondary information, may not always work)
detect_distro_info() {
    log_info "Attempting to detect distribution name and version..."
    
    # Try /etc/os-release first (most modern systems)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_NAME="${NAME:-$ID}"
        DISTRO_VERSION="${VERSION_ID:-$VERSION}"
        log_debug "From /etc/os-release: $DISTRO_NAME $DISTRO_VERSION"
    
    # Try specific release files
    elif [ -f /etc/redhat-release ]; then
        DISTRO_NAME=$(cat /etc/redhat-release | awk '{print $1}')
        DISTRO_VERSION=$(cat /etc/redhat-release | grep -oP '\d+(\.\d+)?' | head -1)
        log_debug "From /etc/redhat-release: $DISTRO_NAME $DISTRO_VERSION"
    
    elif [ -f /etc/debian_version ]; then
        DISTRO_NAME="Debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        log_debug "From /etc/debian_version: $DISTRO_NAME $DISTRO_VERSION"
    
    elif [ -f /etc/alpine-release ]; then
        DISTRO_NAME="Alpine"
        DISTRO_VERSION=$(cat /etc/alpine-release)
        log_debug "From /etc/alpine-release: $DISTRO_NAME $DISTRO_VERSION"
    
    elif [ -f /etc/arch-release ]; then
        DISTRO_NAME="Arch Linux"
        DISTRO_VERSION="rolling"
        log_debug "From /etc/arch-release: $DISTRO_NAME"
    
    elif [ -f /etc/gentoo-release ]; then
        DISTRO_NAME="Gentoo"
        DISTRO_VERSION=$(cat /etc/gentoo-release | grep -oP '\d+(\.\d+)?')
        log_debug "From /etc/gentoo-release: $DISTRO_NAME $DISTRO_VERSION"
    
    elif [ -f /etc/oracle-release ]; then
        DISTRO_NAME="Oracle Linux"
        DISTRO_VERSION=$(cat /etc/oracle-release | grep -oP '\d+(\.\d+)?' | head -1)
        log_debug "From /etc/oracle-release: $DISTRO_NAME $DISTRO_VERSION"
    
    else
        DISTRO_NAME="Unknown"
        DISTRO_VERSION="unknown"
        log_warn "Could not determine distribution name/version"
    fi
}

# Display comprehensive detection summary
display_detection_summary() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}     System Detection Summary${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "Distribution:     ${CYAN}${DISTRO_NAME} ${DISTRO_VERSION}${NC}"
    echo -e "Distro Family:    ${CYAN}${DISTRO_FAMILY}${NC}"
    echo -e "Package Manager:  ${CYAN}${PACKAGE_MANAGER}${NC}"
    echo -e "Service Manager:  ${CYAN}${SERVICE_MANAGER}${NC}"
    echo -e "Python:           ${CYAN}${PYTHON_CMD:-not found}${NC}"
    if [ -n "${PYTHON_VERSION:-}" ]; then
        echo -e "Python Version:   ${CYAN}${PYTHON_VERSION}${NC}"
    fi
    echo -e "${GREEN}=========================================${NC}"
    echo ""
}

# Install Python if not present
install_python() {
    if [ -z "$PYTHON_CMD" ]; then
        log_info "Installing Python..."
        case $PACKAGE_MANAGER in
            apt)
                apt-get update -y && apt-get install -y python3 python3-pip
                ;;
            dnf|yum)
                $PACKAGE_MANAGER install -y python3 python3-pip
                ;;
            apk)
                apk add python3 py3-pip
                ;;
            pacman)
                pacman -Sy --noconfirm python python-pip
                ;;
            zypper)
                zypper install -y python3 python3-pip
                ;;
            emerge)
                emerge dev-lang/python
                ;;
            *)
                log_error "Cannot automatically install Python for this package manager"
                return 1
                ;;
        esac
        detect_python
    fi
}

# Install Ansible using APT (Debian, Ubuntu, Devuan, etc.)
install_with_apt() {
    log_info "Installing Ansible using APT..."
    
    # Update package list
    apt-get update -y
    
    # Install dependencies
    apt-get install -y python3 python3-pip
    
    # Try to install software-properties-common (for add-apt-repository)
    apt-get install -y software-properties-common 2>/dev/null || {
        log_warn "software-properties-common not available (normal for minimal systems)"
    }
    
    # Try to add Ansible PPA (works on Ubuntu, may fail on Debian/Devuan)
    if command -v add-apt-repository &> /dev/null; then
        add-apt-repository --yes --update ppa:ansible/ansible 2>/dev/null || {
            log_warn "Ansible PPA not available, using default repositories"
        }
        apt-get update -y
    fi
    
    # Install ansible
    apt-get install -y ansible || {
        log_warn "Package manager install failed, trying pip..."
        pip3 install ansible
    }
    
    # Special note for sysvinit systems
    if [ "$SERVICE_MANAGER" = "sysvinit" ]; then
        log_info "Detected SysVinit - Ansible will work without systemd dependencies"
    fi
}

# Install Ansible using DNF (Fedora, RHEL 8+, Rocky, Alma)
install_with_dnf() {
    log_info "Installing Ansible using DNF..."
    
    # Try to enable EPEL if needed (not needed on Fedora)
    if ! dnf repolist 2>/dev/null | grep -q "epel"; then
        log_info "Attempting to enable EPEL repository..."
        dnf install -y epel-release 2>/dev/null || {
            log_warn "EPEL not available (may not be needed)"
        }
    fi
    
    # Install Ansible
    dnf install -y ansible python3
}

# Install Ansible using YUM (CentOS 7, RHEL 7, Oracle Linux)
install_with_yum() {
    log_info "Installing Ansible using YUM..."
    
    # Enable EPEL repository
    if [ ! -f /etc/yum.repos.d/epel.repo ]; then
        log_info "Installing EPEL repository..."
        
        # Check for Oracle Linux
        if [ -f /etc/oracle-release ]; then
            if grep -q "release 9" /etc/oracle-release 2>/dev/null; then
                yum install -y oracle-epel-release-el9
            elif grep -q "release 8" /etc/oracle-release 2>/dev/null; then
                yum install -y oracle-epel-release-el8
            elif grep -q "release 7" /etc/oracle-release 2>/dev/null; then
                yum install -y oracle-epel-release-el7
            fi
        else
            # Regular EPEL for CentOS/RHEL
            yum install -y epel-release
        fi
    fi
    
    # Install Ansible
    yum install -y ansible python3 || {
        log_warn "Package install failed, trying pip..."
        yum install -y python3-pip
        pip3 install ansible
    }
}

# Install Ansible using APK (Alpine Linux)
install_with_apk() {
    log_info "Installing Ansible using APK..."
    
    # Update package index
    apk update
    
    # Install ansible and dependencies
    apk add ansible python3 py3-pip
    
    log_info "OpenRC detected - Ansible services will use OpenRC"
}

# Install Ansible using Pacman (Arch, Manjaro)
install_with_pacman() {
    log_info "Installing Ansible using Pacman..."
    
    # Update package database
    pacman -Sy
    
    # Install ansible
    pacman -S --noconfirm ansible python
}

# Install Ansible using Zypper (openSUSE, SLES)
install_with_zypper() {
    log_info "Installing Ansible using Zypper..."
    
    zypper refresh
    zypper install -y ansible python3
}

# Install Ansible using Emerge (Gentoo)
install_with_emerge() {
    log_info "Installing Ansible using Emerge..."
    
    emerge --sync
    emerge -av app-admin/ansible
}

# Install Ansible using pip (fallback method)
install_with_pip() {
    log_warn "Using pip as fallback installation method..."
    
    # Make sure we have pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_error "pip not available and cannot install it automatically"
        log_error "Please install python3-pip manually for your distribution"
        exit 1
    fi
    
    # Use pip3 if available, otherwise pip
    if command -v pip3 &> /dev/null; then
        pip3 install --upgrade pip
        pip3 install ansible
    else
        pip install --upgrade pip
        pip install ansible
    fi
}

# Main installation router based on package manager
install_ansible() {
    log_info "Starting Ansible installation..."
    mkdir -p $PLAYBOOK_DIR
    
    # Ensure Python is installed first
    install_python
    
    case $PACKAGE_MANAGER in
        apt)
            install_with_apt
            ;;
        dnf)
            install_with_dnf
            ;;
        yum)
            install_with_yum
            ;;
        apk)
            install_with_apk
            ;;
        pacman)
            install_with_pacman
            ;;
        zypper)
            install_with_zypper
            ;;
        emerge)
            install_with_emerge
            ;;
        none|unknown)
            log_warn "No package manager detected, using pip..."
            install_with_pip
            ;;
        *)
            log_error "Unsupported package manager: $PACKAGE_MANAGER"
            log_info "Attempting pip installation as fallback..."
            install_with_pip
            ;;
    esac
}

# Verify Ansible installation
verify_installation() {
    log_info "Verifying Ansible installation..."
    
    if command -v ansible &> /dev/null; then
        ANSIBLE_VERSION=$(ansible --version | head -n1)
        log_success "✓ $ANSIBLE_VERSION"
        
        # Display ansible location
        log_info "Ansible executable: $(command -v ansible)"
        
        # Display ansible config
        if command -v ansible-config &> /dev/null; then
            ANSIBLE_CONFIG=$(ansible-config view 2>/dev/null | grep DEFAULT_MODULE_PATH | head -1)
            [ -n "$ANSIBLE_CONFIG" ] && log_debug "Config: $ANSIBLE_CONFIG"
        fi
        
        # Test ansible
        echo ""
        log_info "Testing Ansible with localhost ping..."
        if ansible localhost -m ping 2>/dev/null | grep -q "SUCCESS"; then
            log_success "✓ Ansible ping test: PASSED"
        else
            log_warn "✗ Ansible ping test: FAILED (may need configuration)"
        fi
        
        return 0
    else
        log_error "Ansible installation failed!"
        log_error "Ansible command not found in PATH"
        return 1
    fi
}

# Display post-installation information
display_postinstall_info() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}     Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Quick start commands:"
    echo -e "  ${CYAN}ansible --version${NC}                  # Check Ansible version"
    echo -e "  ${CYAN}ansible localhost -m ping${NC}          # Test local connectivity"
    echo -e "  ${CYAN}ansible-playbook playbook.yml${NC}      # Run a playbook"
    echo -e "  ${CYAN}ansible-galaxy install <role>${NC}      # Install Ansible roles"
    echo ""
    echo "Ansible configuration:"
    echo -e "  System config: ${CYAN}/etc/ansible/ansible.cfg${NC}"
    echo -e "  User config:   ${CYAN}~/.ansible.cfg${NC}"
    echo ""
    echo "CCDC Quick Tips:"
    echo -e "  • Create inventory file with target hosts"
    echo -e "  • Use ${CYAN}--ask-pass${NC} for password authentication"
    echo -e "  • Use ${CYAN}--become${NC} for privilege escalation"
    echo -e "  • Use ${CYAN}-f N${NC} for parallel execution (N hosts)"
    echo ""
}

# Main function
main() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════╗"
    echo "║  Universal Ansible Installer - CCDC   ║"
    echo "║  Package & Service Manager Detection  ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    
    log_info "Starting system detection..."
    detect_package_manager
    detect_service_manager
    detect_python
    detect_distro_info
    
    display_detection_summary
    
    log_info "Proceeding with installation based on detected system..."
    install_ansible
    
    echo ""
    if verify_installation; then
        display_postinstall_info
        exit 0
    else
        log_error "Installation verification failed"
        exit 1
    fi
}

# Run main function
main "$@"
