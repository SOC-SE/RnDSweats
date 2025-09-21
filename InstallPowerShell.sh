# ==============================================================================
# File: Liaison/InstallPowerShell.sh
# Description: Installs Microsoft PowerShell on compatible Linux distributions (Debian, Ubuntu, Fedora, CentOS/RHEL)
#              as per the 2025 MWCCDC Team Pack. If PowerShell is not installed, it sets up the repository and installs it.
#              If already installed, prompts the user to uninstall and performs a clean removal (package, repo files, etc.).
#              Supports apt (Debian/Ubuntu) and dnf/yum (Fedora/CentOS/RHEL). Based on official Microsoft instructions
#              for PowerShell 7.5 (latest as of July 2025).
#
# Usage: sudo ./InstallPowerShell.sh
# Notes:
# - Run as root.
# - After installation, run PowerShell with 'pwsh'. Use it for scripting, e.g., pwsh -Command "Get-Process".
# - In CCDC VMs, ensure internet access for downloads (allowed for patches). No conflicts with Palo Alto or services.
# - For uninstall, removes package, repo configs, and cleans up temporary files.
# ==============================================================================

#!/bin/bash

set -euo pipefail

# --- Configuration & Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
DEB_FILE="packages-microsoft-prod.deb"
REPO_FILE="/etc/yum.repos.d/microsoft.repo"  # For rpm
APT_REPO_FILE="/etc/apt/sources.list.d/microsoft-prod.list"  # For apt

# --- Helper Functions ---
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# --- Root Check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
    fi
}

# --- Detect Package Manager ---
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        REMOVE_CMD="apt-get remove -y"
        AUTOREMOVE_CMD="apt-get autoremove -y"
        UPDATE_CMD="apt-get update"
        PREREQ_PKGS="wget apt-transport-https software-properties-common"
        DISTRO_PATH="ubuntu"  # Default to ubuntu; adjust for debian
        if grep -q 'ID=debian' /etc/os-release; then
            DISTRO_PATH="debian"
            PREREQ_PKGS="wget apt-transport-https"
        fi
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        REMOVE_CMD="dnf remove -y"
        AUTOREMOVE_CMD="dnf autoremove -y"
        UPDATE_CMD="dnf update"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        REMOVE_CMD="yum remove -y"
        AUTOREMOVE_CMD="yum autoremove -y"
        UPDATE_CMD="yum update"
    else
        log_error "Unsupported package manager. Only apt (Debian/Ubuntu), dnf (Fedora/RHEL), and yum (CentOS/RHEL) are supported."
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# --- Check if PowerShell Installed ---
is_powershell_installed() {
    command -v pwsh &> /dev/null
}

# --- Install PowerShell ---
install_powershell() {
    log_info "Installing PowerShell..."
    
    printf "Installing PowerShell... "
    local err_file=$(mktemp)
    if [ "$PKG_MANAGER" = "apt" ]; then
        ( $UPDATE_CMD >/dev/null 2>"$err_file"
          $INSTALL_CMD $PREREQ_PKGS >/dev/null 2>>"$err_file"
          wget -q "https://packages.microsoft.com/config/$DISTRO_PATH/$(lsb_release -rs)/$DEB_FILE" >/dev/null 2>>"$err_file"
          dpkg -i "$DEB_FILE" >/dev/null 2>>"$err_file"
          $UPDATE_CMD >/dev/null 2>>"$err_file"
          $INSTALL_CMD powershell >/dev/null 2>>"$err_file"
          rm -f "$DEB_FILE" >/dev/null 2>>"$err_file" ) &
    else  # dnf or yum
        ( rpm --import https://packages.microsoft.com/keys/microsoft.asc >/dev/null 2>"$err_file"
          if [ "$PKG_MANAGER" = "yum" ]; then
              VERSION_ID=$(rpm -E %rhel)
          else
              VERSION_ID=$(rpm -E %fedora || rpm -E %rhel)
          fi
          wget -q -O "$REPO_FILE" "https://packages.microsoft.com/config/rhel/$VERSION_ID/prod.repo" >/dev/null 2>>"$err_file"
          $UPDATE_CMD >/dev/null 2>>"$err_file"
          $INSTALL_CMD powershell >/dev/null 2>>"$err_file" ) &
    fi
    local pid=$!
    spinner $pid
    wait $pid
    local exit_status=$?
    local err_content=$(cat "$err_file")
    rm -f "$err_file"
    if [ $exit_status -ne 0 ]; then
        echo ""  # Newline after spinner
        echo -e "${RED}Error during PowerShell installation:${NC}"
        echo "$err_content"
        log_error "❌ PowerShell installation failed!"
    fi
    echo ""  # Newline
    
    # Verify installation
    if is_powershell_installed; then
        log_info "✅ PowerShell installed successfully!"
        log_info "Version: $(pwsh --version)"
        
        # Offer to start PowerShell immediately
        echo ""
        log_info "PowerShell is ready to use!"
        read -p "Would you like to start PowerShell now? (y/n): " start_now
        case "$start_now" in
            y|Y ) start_powershell_interactive ;;
            * ) show_powershell_usage ;;
        esac
    else
        log_error "❌ PowerShell installation failed!"
    fi
}

# --- Uninstall PowerShell ---
uninstall_powershell() {
    log_info "Uninstalling PowerShell..."
    
    $REMOVE_CMD powershell
    $AUTOREMOVE_CMD
    
    # Clean up repo files
    if [ "$PKG_MANAGER" = "apt" ]; then
        rm -f "$DEB_FILE" "$APT_REPO_FILE"
        $UPDATE_CMD  # Refresh after removal
    else
        rm -f "$REPO_FILE"
    fi
    
    log_info "PowerShell uninstalled and cleaned up successfully."
}

# --- Show PowerShell Usage Instructions ---
show_powershell_usage() {
    echo ""
    log_info "PowerShell Usage Instructions:"
    echo "================================"
    echo "• Start PowerShell: pwsh"
    echo "• Run single command: pwsh -Command 'Get-Process'"
    echo "• Run script file: pwsh /path/to/script.ps1"
    echo "• Exit PowerShell: exit (or Ctrl+D)"
    echo ""
    echo "Basic PowerShell Commands:"
    echo "• Get-Process              - List running processes"
    echo "• Get-Service              - List system services"
    echo "• Get-ChildItem            - List directory contents (like 'ls' or 'dir')"
    echo "• Set-Location <path>      - Change directory (like 'cd')"
    echo "• Get-Help <command>       - Get help for any command"
    echo "• Write-Host 'Hello'       - Print text to console"
    echo ""
    log_info "For CCDC: Use PowerShell for Windows-like scripting and automation!"
}

# --- Start PowerShell Interactive Session ---
start_powershell_interactive() {
    echo ""
    log_info "Starting PowerShell Interactive Session..."
    log_info "=========================================="
    echo ""
    echo "PowerShell Quick Reference:"
    echo "• Type commands and press Enter"
    echo "• Use 'exit' or press Ctrl+D to quit"
    echo "• Try: Get-Process, Get-Service, Get-ChildItem"
    echo "• Type 'help' for more information"
    echo ""
    log_info "Launching PowerShell now..."
    echo ""
    
    # Start PowerShell
    pwsh
    
    # After PowerShell exits
    echo ""
    log_info "PowerShell session ended."
    log_info "You can restart anytime with: pwsh"
}

# --- Verify PowerShell Installation ---
verify_powershell() {
    if is_powershell_installed; then
        log_info "✅ PowerShell is installed"
        log_info "Version: $(pwsh --version)"
        
        # Test basic functionality
        log_info "Testing PowerShell functionality..."
        if pwsh -Command "Write-Host 'PowerShell test successful!'" &>/dev/null; then
            log_info "✅ PowerShell is working correctly"
        else
            log_warn "⚠️  PowerShell installed but basic test failed"
        fi
        
        return 0
    else
        log_error "❌ PowerShell is not installed"
        return 1
    fi
}

# --- Main Logic ---
main() {
    check_root
    detect_pkg_manager
    
    if ! is_powershell_installed; then
        install_powershell
    else
        log_warn "PowerShell is already installed."
        verify_powershell
        
        echo ""
        read -p "Would you like to start PowerShell now? (y/n): " start_choice
        case "$start_choice" in
            y|Y ) start_powershell_interactive ;;
            * ) 
                read -p "Would you like to uninstall PowerShell? (y/n): " uninstall_choice
                case "$uninstall_choice" in
                    y|Y ) uninstall_powershell ;;
                    * ) show_powershell_usage ;;
                esac
                ;;
        esac
    fi
    
    log_info "${GREEN}--- Script Complete ---${NC}"
}

main "$@"
