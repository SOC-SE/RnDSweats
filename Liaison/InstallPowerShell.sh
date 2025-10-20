#!/bin/bash

# ============================================================================== 
# File: Liaison/InstallPowerShell.sh
# Description: Installs Microsoft PowerShell on supported Linux distributions.
#              Supports apt (Debian/Ubuntu and derivatives) and dnf/yum (Fedora,
#              RHEL, CentOS, Oracle Linux) as outlined in the 2025 MWCCDC Team
#              Pack. Provides guided uninstall and post-install verification.
# ============================================================================== 

set -euo pipefail

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

DEB_FILE="packages-microsoft-prod.deb"
APT_REPO_FILE="/etc/apt/sources.list.d/microsoft-prod.list"
REPO_FILE="/etc/yum.repos.d/microsoft-powershell.repo"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

die() {
    log_error "$1"
    exit 1
}

check_root() {
    if [ "${EUID}" -ne 0 ]; then
        die "This script must be run as root or with sudo."
    fi
}

require_commands() {
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Required command '$cmd' is not available."
        fi
    done
}

# Detect the active package manager and distro metadata used for repository setup.
detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        REMOVE_CMD="apt-get remove -y"
        AUTOREMOVE_CMD="apt-get autoremove -y"
        UPDATE_CMD="apt-get update"
        PREREQ_PKGS="wget apt-transport-https software-properties-common gnupg"

        if [ -r /etc/os-release ]; then
            . /etc/os-release
            DIST_ID=${ID:-ubuntu}
            DIST_VERSION=${VERSION_ID:-"22.04"}
            UBUNTU_CODENAME=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
        else
            DIST_ID="ubuntu"
            DIST_VERSION="22.04"
            UBUNTU_CODENAME=""
        fi

        case "$DIST_ID" in
            ubuntu)
                DISTRO_PATH="ubuntu"
                DISTRO_VERSION_PATH=${DIST_VERSION}
                ;;
            debian)
                DISTRO_PATH="debian"
                DISTRO_VERSION_PATH=${DIST_VERSION%%.*}
                ;;
            pop|elementary|linuxmint)
                DISTRO_PATH="ubuntu"
                DISTRO_VERSION_PATH=${UBUNTU_CODENAME:-${DIST_VERSION}}
                ;;
            *)
                DISTRO_PATH="ubuntu"
                DISTRO_VERSION_PATH=${DIST_VERSION}
                ;;
        esac
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        REMOVE_CMD="dnf remove -y"
        AUTOREMOVE_CMD="dnf autoremove -y"
        UPDATE_CMD="dnf makecache -y"

        if [ -r /etc/os-release ]; then
            . /etc/os-release
            OS_ID=${ID:-rhel}
            OS_VER=${VERSION_ID%%.*}
        else
            OS_ID="rhel"
            OS_VER="8"
        fi
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        REMOVE_CMD="yum remove -y"
        AUTOREMOVE_CMD="yum autoremove -y"
        UPDATE_CMD="yum makecache -y"

        if [ -r /etc/os-release ]; then
            . /etc/os-release
            OS_ID=${ID:-rhel}
            OS_VER=${VERSION_ID%%.*}
        else
            OS_ID="rhel"
            OS_VER="8"
        fi
    else
        die "Unsupported package manager. Supported: apt, dnf, or yum."
    fi

    log_info "Detected package manager: ${PKG_MANAGER}"
}

is_powershell_installed() {
    command -v pwsh >/dev/null 2>&1
}

install_powershell() {
    log_info "Starting PowerShell installation..."

    local err_file err_content KEY_TMP repo_url repo_base start_now

    err_file=$(mktemp)
    trap 'rm -f "$err_file"' RETURN

    case "$PKG_MANAGER" in
        apt)
            require_commands wget dpkg

            log_info "Updating package cache..."
            if ! $UPDATE_CMD &>>"$err_file"; then
                cat "$err_file"
                die "Failed to update apt package lists."
            fi

            log_info "Installing prerequisites (${PREREQ_PKGS})..."
            if ! $INSTALL_CMD $PREREQ_PKGS &>>"$err_file"; then
                cat "$err_file"
                die "Failed to install prerequisite packages."
            fi

            repo_url="https://packages.microsoft.com/config/${DISTRO_PATH}/${DISTRO_VERSION_PATH}/packages-microsoft-prod.deb"
            log_info "Downloading Microsoft repository package (${repo_url})..."
            if ! wget -qO "$DEB_FILE" "$repo_url" &>>"$err_file"; then
                cat "$err_file"
                die "Failed to download Microsoft repository package."
            fi

            log_info "Configuring Microsoft repository..."
            if ! dpkg -i "$DEB_FILE" &>>"$err_file"; then
                cat "$err_file"
                die "Failed to install repository package."
            fi
            rm -f "$DEB_FILE"

            log_info "Refreshing package lists..."
            if ! $UPDATE_CMD &>>"$err_file"; then
                cat "$err_file"
                die "Failed to refresh apt package lists after adding repository."
            fi

            log_info "Installing PowerShell via apt..."
            if ! $INSTALL_CMD powershell &>>"$err_file"; then
                cat "$err_file"
                die "PowerShell installation failed."
            fi
            ;;
        dnf|yum)
            require_commands wget rpm

            if ! command -v gpg >/dev/null 2>&1; then
                log_info "Installing gnupg for key import..."
                $INSTALL_CMD gnupg &>>"$err_file" || true
            fi

            KEY_TMP=$(mktemp)
            repo_base="rhel"
            case "$OS_ID" in
                fedora)
                    repo_base="fedora"
                    ;;
                ol|olinux|oraclelinux)
                    repo_base="rhel"
                    ;;
            esac

            log_info "Importing Microsoft GPG key..."
            if ! wget -qO "$KEY_TMP" "https://packages.microsoft.com/keys/microsoft.asc" &>>"$err_file"; then
                cat "$err_file"
                die "Failed to download Microsoft GPG key."
            fi
            if ! rpm --import "$KEY_TMP" &>>"$err_file"; then
                cat "$err_file"
                die "Failed to import Microsoft GPG key."
            fi
            rm -f "$KEY_TMP"

            repo_url="https://packages.microsoft.com/config/${repo_base}/${OS_VER}/prod.repo"
            log_info "Downloading Microsoft repository config (${repo_url})..."
            if ! wget -qO "$REPO_FILE" "$repo_url" &>>"$err_file"; then
                cat "$err_file"
                die "Failed to download repository configuration."
            fi

            log_info "Updating repository metadata..."
            if ! $UPDATE_CMD &>>"$err_file"; then
                cat "$err_file"
                die "Failed to update RPM repository metadata."
            fi

            log_info "Installing PowerShell via ${PKG_MANAGER}..."
            if ! $INSTALL_CMD powershell &>>"$err_file"; then
                cat "$err_file"
                die "PowerShell installation failed."
            fi
            ;;
    esac

    err_content=$(cat "$err_file" 2>/dev/null || true)
    rm -f "$err_file"
    trap - RETURN
    if [ -n "$err_content" ]; then
        log_warn "Installation completed with warnings: $err_content"
    fi

    if is_powershell_installed; then
        log_info "✅ PowerShell installed successfully."
        log_info "Version: $(pwsh -c '$PSVersionTable.PSVersion' 2>/dev/null || pwsh --version)"
    else
        die "PowerShell installation completed but pwsh not detected."
    fi

    log_info "PowerShell is ready to use."
    read -p "Would you like to start PowerShell now? (y/n): " start_now
    case "$start_now" in
        y|Y) start_powershell_interactive ;;
        *)  show_powershell_usage ;;
    esac
}

uninstall_powershell() {
    log_info "Uninstalling PowerShell..."

    case "$PKG_MANAGER" in
        apt)
            $REMOVE_CMD powershell &>/dev/null || true
            $AUTOREMOVE_CMD &>/dev/null || true
            rm -f "$DEB_FILE" "$APT_REPO_FILE" &>/dev/null || true
            $UPDATE_CMD &>/dev/null || true
            ;;
        dnf|yum)
            $REMOVE_CMD powershell &>/dev/null || true
            $AUTOREMOVE_CMD &>/dev/null || true
            rm -f "$REPO_FILE" &>/dev/null || true
            ;;
    esac

    log_info "PowerShell removal complete."
}

show_powershell_usage() {
    echo ""
    log_info "PowerShell Usage Quick Reference"
    echo "================================"
    echo "- Start PowerShell: pwsh"
    echo "- Run one-liner:   pwsh -Command 'Get-Process'"
    echo "- Run script:      pwsh /path/to/script.ps1"
    echo "- Exit shell:      exit (or Ctrl+D)"
    echo ""
    echo "Common Commands"
    echo "- Get-Process      - List running processes"
    echo "- Get-Service      - List system services"
    echo "- Get-ChildItem    - List directory contents"
    echo "- Set-Location     - Change directory"
    echo "- Get-Help <cmd>   - Show command help"
    echo ""
    log_info "Great for cross-platform scripting during CCDC."
}

start_powershell_interactive() {
    echo ""
    log_info "Launching PowerShell interactive session..."
    echo "Use 'exit' or Ctrl+D to leave the shell."
    echo "Try commands like Get-Process, Get-Service, Get-ChildItem."
    echo ""
    pwsh || log_warn "PowerShell exited with a non-zero status."
    echo ""
    log_info "PowerShell session ended. Relaunch anytime with 'pwsh'."
}

verify_powershell() {
    if is_powershell_installed; then
        log_info "✅ PowerShell present."
        log_info "Version: $(pwsh -c '$PSVersionTable.PSVersion' 2>/dev/null || pwsh --version)"
        log_info "Running smoke test..."
        if pwsh -Command "Write-Host 'PowerShell test successful!'" &>/dev/null; then
            log_info "✅ PowerShell responded to test command."
        else
            log_warn "PowerShell installed but test command failed."
        fi
        return 0
    fi

    log_error "PowerShell is not installed."
    return 1
}

main() {
    check_root
    detect_pkg_manager

    if ! is_powershell_installed; then
        install_powershell
    else
        log_warn "PowerShell already installed."
        verify_powershell
        echo ""
        read -p "Would you like to start PowerShell now? (y/n): " start_choice
        case "$start_choice" in
            y|Y) start_powershell_interactive ;;
            *)
                read -p "Would you like to uninstall PowerShell? (y/n): " uninstall_choice
                case "$uninstall_choice" in
                    y|Y) uninstall_powershell ;;
                    *)   show_powershell_usage ;;
                esac
                ;;
        esac
    fi

    log_info "${GREEN}--- Script Complete ---${NC}"
}

main "$@"
