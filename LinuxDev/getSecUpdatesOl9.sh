#!/bin/bash

# All Security Updates Script for Oracle Linux 9.2
# This script applies Critical, Important, and Moderate security updates for essential packages
# More comprehensive than critical-only but still focused on core system packages

# Valid switchs are:
# ./get_all_security_updates_ol9.sh preview
# ./get_all_security_updates_ol9.sh install

set -euo pipefail

# Configuration
LOG_FILE="/var/log/all_security_updates.log"
DRY_RUN=${1:-"preview"}  # preview, install
DOWNLOAD_CACHE="/var/cache/dnf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check system version
check_system() {
    if ! grep -q "Oracle Linux.*release 9" /etc/oracle-release 2>/dev/null; then
        if ! grep -q "Oracle Linux.*release 9" /etc/redhat-release 2>/dev/null; then
            error_exit "This script is designed for Oracle Linux 9.x"
        fi
    fi
    log "System check passed: $(cat /etc/oracle-release 2>/dev/null || cat /etc/redhat-release)"
}

# Define critical packages patterns
get_critical_packages() {
    cat << 'EOF'
# Critical security packages (high priority)
kernel*
sudo*
glibc*
openssl*
systemd*
openssh*
# Authentication and privilege escalation fixes
pam*
polkit*
# Network security
bind*
unbound*
# Container security (if applicable)
podman*
runc*
EOF
}

# Get list of available security updates (Critical, Important, and Moderate)
get_all_security_updates() {
    log "Checking for all security updates (Critical, Important, Moderate)..."
    
    # Get all security advisories - expanded to include Moderate severity
    dnf updateinfo list security 2>/dev/null | grep -E "(Critical|Important|Moderate)" | while read -r line; do
        advisory=$(echo "$line" | awk '{print $1}')
        severity=$(echo "$line" | awk '{print $2}')
        package=$(echo "$line" | awk '{print $3}')
        
        # Filter for critical packages only
        if echo "$package" | grep -qE "^(kernel|sudo|glibc|openssl|systemd|openssh|pam|polkit|bind|unbound|podman|runc)"; then
            echo "$advisory $severity $package"
        fi
    done
}

# Preview security updates
preview_updates() {
    echo -e "${BLUE}=== ALL SECURITY UPDATES PREVIEW ===${NC}"
    log "Starting preview of all security updates (Critical, Important, Moderate)"
    
    local security_updates
    security_updates=$(get_all_security_updates)
    
    if [[ -z "$security_updates" ]]; then
        echo -e "${GREEN}No security updates available for essential packages${NC}"
        log "No security updates found"
        return 0
    fi
    
    # Separate by severity for better display
    local critical_updates important_updates moderate_updates
    critical_updates=$(echo "$security_updates" | grep "Critical" || true)
    important_updates=$(echo "$security_updates" | grep "Important" || true) 
    moderate_updates=$(echo "$security_updates" | grep "Moderate" || true)
    
    # Display by severity
    if [[ -n "$critical_updates" ]]; then
        echo -e "${RED}Critical security updates:${NC}"
        echo "$critical_updates" | while read -r advisory severity package; do
            echo -e "  ${RED}$severity${NC}: $package ($advisory)"
        done
        echo
    fi
    
    if [[ -n "$important_updates" ]]; then
        echo -e "${YELLOW}Important security updates:${NC}"
        echo "$important_updates" | while read -r advisory severity package; do
            echo -e "  ${YELLOW}$severity${NC}: $package ($advisory)"
        done
        echo
    fi
    
    if [[ -n "$moderate_updates" ]]; then
        echo -e "${BLUE}Moderate security updates:${NC}"
        echo "$moderate_updates" | while read -r advisory severity package; do
            echo -e "  ${BLUE}$severity${NC}: $package ($advisory)"
        done
        echo
    fi
    
    # Estimate download size
    echo -e "${BLUE}Estimating download size...${NC}"
    local packages_list
    packages_list=$(echo "$security_updates" | awk '{print $3}' | sort -u)
    
    if [[ -n "$packages_list" ]]; then
        # Use dnf to check download size
        echo "$packages_list" | xargs dnf update --downloadonly --assumeno 2>&1 | \
            grep -E "(Total download size|Nothing to do)" || true
    fi
    
    echo -e "\n${YELLOW}Note:${NC} This includes Moderate severity updates, so download size may be larger than critical-only scripts"
    echo -e "\n${YELLOW}Next step:${NC}"
    echo "  Run with 'install' to download and install: $0 install"
}

# Install security updates
install_updates() {
    echo -e "${BLUE}=== INSTALLING ALL SECURITY UPDATES ===${NC}"
    log "Starting installation of all security updates (Critical, Important, Moderate)"
    
    local security_updates
    security_updates=$(get_all_security_updates)
    
    if [[ -z "$security_updates" ]]; then
        echo -e "${GREEN}No security updates to install${NC}"
        return 0
    fi
    
    # Create system backup info
    echo -e "${YELLOW}Creating backup information...${NC}"
    rpm -qa > "/tmp/rpm_backup_$(date +%Y%m%d_%H%M%S).txt"
    uname -r > "/tmp/kernel_backup_$(date +%Y%m%d_%H%M%S).txt"
    
    local packages_list
    packages_list=$(echo "$security_updates" | awk '{print $3}' | sort -u)
    
    # Show what will be installed by severity
    echo -e "${YELLOW}Installing security updates by severity:${NC}"
    echo "$security_updates" | awk '{print $2}' | sort | uniq -c | while read -r count severity; do
        echo "  $severity: $count packages"
    done
    echo
    
    # Install packages
    echo -e "${YELLOW}Installing all security updates...${NC}"
    echo "$packages_list" | xargs dnf update --assumeyes
    
    # Check if kernel was updated
    if echo "$packages_list" | grep -q "kernel"; then
        echo -e "${RED}KERNEL UPDATED - REBOOT REQUIRED${NC}"
        log "Kernel updated - system reboot required"
        echo -e "${YELLOW}Please reboot the system to use the new kernel${NC}"
        echo "Current kernel: $(uname -r)"
        echo "New kernel(s) installed:"
        rpm -qa kernel* | grep -v "$(uname -r)" | sort
    fi
    
    # Check for systemd updates (may require service restarts)
    if echo "$packages_list" | grep -q "systemd"; then
        echo -e "${YELLOW}SystemD updated - consider restarting services or rebooting${NC}"
        log "SystemD updated - services may need restart"
    fi
    
    log "All security updates installation completed"
    echo -e "${GREEN}All security updates installed successfully${NC}"
}

# Cleanup function
cleanup() {
    # Clean dnf cache if requested
    if [[ "${CLEAN_CACHE:-}" == "yes" ]]; then
        dnf clean all
    fi
}

# Main function
main() {
    echo -e "${BLUE}Oracle Linux 9.2 All Security Updates${NC}"
    echo "====================================="
    
    check_root
    check_system
    
    case "${DRY_RUN}" in
        "preview"|"")
            preview_updates
            ;;
        "install")
            install_updates
            ;;
        *)
            echo "Usage: $0 [preview|install]"
            echo "  preview  - Show what updates are available (default)"
            echo "  install  - Download and install all security updates"
            echo ""
            echo "Environment variables:"
            echo "  CLEAN_CACHE=yes  - Clean dnf cache after operation"
            exit 1
            ;;
    esac
    
    cleanup
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main