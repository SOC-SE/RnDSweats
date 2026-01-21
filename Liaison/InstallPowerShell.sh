#!/bin/bash

# PowerShell Install Script

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
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

die() { log_error "$1"; }

check_root() {
    if [ "${EUID}" -ne 0 ]; then
        die "Run as root or with sudo."
    fi
}

require_commands() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "Missing '$cmd'."
    done
}

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
        fi

        case "$DIST_ID" in
            ubuntu|debian) DISTRO_PATH="$DIST_ID"; DISTRO_VERSION_PATH=${DIST_VERSION%%.*} ;;
            pop|elementary|linuxmint) DISTRO_PATH="ubuntu"; DISTRO_VERSION_PATH=${UBUNTU_CODENAME:-${DIST_VERSION}} ;;
            *) DISTRO_PATH="ubuntu"; DISTRO_VERSION_PATH=${DIST_VERSION} ;;
        esac
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        REMOVE_CMD="dnf remove -y"
        AUTOREMOVE_CMD="dnf autoremove -y"
        UPDATE_CMD="dnf makecache -y"
        if [ -r /etc/os-release ]; then . /etc/os-release; OS_ID=${ID:-rhel}; OS_VER=${VERSION_ID%%.*}; fi
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        REMOVE_CMD="yum remove -y"
        AUTOREMOVE_CMD="yum autoremove -y"
        UPDATE_CMD="yum makecache -y"
        if [ -r /etc/os-release ]; then . /etc/os-release; OS_ID=${ID:-rhel}; OS_VER=${VERSION_ID%%.*}; fi
    else
        die "Unsupported package manager."
    fi
    log_info "Package manager: ${PKG_MANAGER}"
}

is_powershell_installed() { command -v pwsh >/dev/null 2>&1; }

install_powershell() {
    log_info "Installing PowerShell..."
    local err_file=$(mktemp); trap 'rm -f "$err_file"' RETURN

    case "$PKG_MANAGER" in
        apt)
            require_commands wget dpkg
            $UPDATE_CMD &>>"$err_file"
            $INSTALL_CMD $PREREQ_PKGS &>>"$err_file"
            local repo_url="https://packages.microsoft.com/config/${DISTRO_PATH}/${DISTRO_VERSION_PATH}/packages-microsoft-prod.deb"
            wget -qO "$DEB_FILE" "$repo_url" &>>"$err_file"
            dpkg -i "$DEB_FILE" &>>"$err_file"; rm -f "$DEB_FILE"
            $UPDATE_CMD &>>"$err_file"
            $INSTALL_CMD powershell &>>"$err_file"
            ;;
        dnf|yum)
            require_commands wget rpm
            command -v gpg >/dev/null 2>&1 || $INSTALL_CMD gnupg &>>"$err_file"
            local KEY_TMP=$(mktemp); wget -qO "$KEY_TMP" "https://packages.microsoft.com/keys/microsoft.asc" &>>"$err_file"; rpm --import "$KEY_TMP"; rm -f "$KEY_TMP"
            local repo_base="rhel"; [[ $OS_ID == "fedora" ]] && repo_base="fedora"
            local repo_url="https://packages.microsoft.com/config/${repo_base}/${OS_VER}/prod.repo"
            wget -qO "$REPO_FILE" "$repo_url" &>>"$err_file"
            $UPDATE_CMD &>>"$err_file"
            $INSTALL_CMD powershell &>>"$err_file"
            ;;
    esac

    local err_content=$(cat "$err_file" 2>/dev/null || true)
    is_powershell_installed || die "Installation failed."
    log_info "PowerShell $(pwsh -c '$PSVersionTable.PSVersion' 2>/dev/null || pwsh --version) installed."
    [ -n "$err_content" ] && log_warn "Warnings: $err_content"
    read -p "Start PowerShell? (y/n): " start_now
    [[ $start_now =~ [yY] ]] && pwsh
}

uninstall_powershell() {
    case "$PKG_MANAGER" in
        apt) $REMOVE_CMD powershell &>/dev/null || true; $AUTOREMOVE_CMD &>/dev/null || true; rm -f "$DEB_FILE" "$APT_REPO_FILE" &>/dev/null || true; $UPDATE_CMD &>/dev/null || true ;;
        dnf|yum) $REMOVE_CMD powershell &>/dev/null || true; $AUTOREMOVE_CMD &>/dev/null || true; rm -f "$REPO_FILE" &>/dev/null || true ;;
    esac
    log_info "PowerShell removed."
}

show_usage() {
    echo "PowerShell Usage:"
    echo "- pwsh (start shell)"
    echo "- pwsh -Command 'Get-Process'"
    echo "- pwsh script.ps1"
}

main() {
    check_root
    detect_pkg_manager
    is_powershell_installed && {
        log_warn "PowerShell installed."
        verify_powershell
        read -p "Start (y), Uninstall (u), or Usage (i)? [s]: " action
        case "${action,,}" in y|s) pwsh ;; u) uninstall_powershell ;; i) show_usage ;; *) show_usage ;; esac
    } || install_powershell
    log_info "Complete."
}

verify_powershell() {
    log_info "Version: $(pwsh -c '$PSVersionTable.PSVersion')"
    pwsh -Command "Write-Host 'Test OK'" &>/dev/null && log_info "Test passed."
}

main "$@"
