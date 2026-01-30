#!/usr/bin/env bash
set -euo pipefail
# ==============================================================================
# Script Name: normalizeTools.sh
# Description: Installs standard security, forensic, and analysis tools across
#              all supported Linux distributions. Includes Docker, Ansible,
#              and optional advanced tools (YARA, Volatility3, AVML).
#              References existing auditd and YARA scripts for full configs.
#
# Author: Samuel Brucker 2025-2026
# Version: 3.0
#
# Supported Systems:
#   - Ubuntu/Debian (apt)
#   - Fedora/RHEL/Oracle/Rocky/Alma (dnf/yum)
#   - Arch (pacman)
#   - Alpine (apk)
#
# Usage:
#   sudo ./normalizeTools.sh
#
# ==============================================================================

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${BLUE}========== $1 ==========${NC}"; }

command_exists() { command -v "$1" > /dev/null 2>&1; }

# Detect distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
else
    DISTRO_ID="unknown"
fi

# Determine package manager
if command_exists apt-get; then
    PKG="apt"
elif command_exists dnf; then
    PKG="dnf"
elif command_exists yum; then
    PKG="yum"
elif command_exists pacman; then
    PKG="pacman"
elif command_exists apk; then
    PKG="apk"
else
    echo "Error: No supported package manager found."
    exit 1
fi

# Helper: install packages by distro
install_pkgs() {
    case "$PKG" in
        apt)    apt-get install -y "$@" 2>/dev/null || true ;;
        dnf)    dnf install -y "$@" 2>/dev/null || true ;;
        yum)    yum install -y "$@" 2>/dev/null || true ;;
        pacman) pacman -S --noconfirm "$@" 2>/dev/null || true ;;
        apk)    apk add "$@" 2>/dev/null || true ;;
    esac
}

# =========================================================================
# 1. ESSENTIAL TOOLS
# =========================================================================
section "ESSENTIAL TOOLS"
log "Installing essential system tools..."

if [[ "$PKG" == "apt" ]]; then
    apt-get update -y
    install_pkgs coreutils findutils binutils file acl attr \
        net-tools lsof strace tcpdump procps psmisc iproute2 \
        iptables bash curl git vim wget grep tar jq gpg nano
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs coreutils findutils binutils file acl attr \
        net-tools lsof strace tcpdump procps-ng psmisc iproute \
        iptables bash curl git vim wget grep tar jq gnupg2 nano
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs coreutils findutils binutils file acl attr \
        net-tools lsof strace tcpdump procps-ng psmisc iproute2 \
        iptables bash curl git vim wget grep tar jq gnupg nano
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs coreutils findutils binutils file acl attr \
        net-tools lsof strace tcpdump procps psmisc iproute2 \
        iptables bash curl git vim wget grep tar jq gnupg nano
fi

log "Essential tools installed."

# =========================================================================
# 2. FORENSIC / SECURITY TOOLS
# =========================================================================
section "FORENSIC & SECURITY TOOLS"
log "Installing security scanning and forensic tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs chkrootkit rkhunter clamav clamav-daemon \
        auditd sysstat unhide debsums
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    # EPEL needed for chkrootkit, rkhunter, unhide on RHEL-family
    install_pkgs epel-release
    install_pkgs chkrootkit rkhunter clamav clamd clamav-update \
        audit sysstat unhide
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs rkhunter clamav audit sysstat unhide
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs rkhunter clamav audit sysstat
fi

# Configure auditd with custom rules if our script exists
AUDITD_SCRIPT="$SCRIPT_DIR/dependencies/auditdSetup.sh"
if [[ -f "$AUDITD_SCRIPT" ]]; then
    log "Running auditd setup with custom audit rules..."
    chmod +x "$AUDITD_SCRIPT"
    bash "$AUDITD_SCRIPT" || warn "auditd setup had errors (non-fatal)"
else
    # Just make sure auditd is enabled
    if command_exists auditctl; then
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
        log "auditd enabled (no custom rules file found at $AUDITD_SCRIPT)"
    fi
fi

log "Forensic & security tools installed."

# =========================================================================
# 3. ANALYSIS TOOLS
# =========================================================================
section "ANALYSIS TOOLS"
log "Installing binary analysis and forensic analysis tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs xxd sleuthkit foremost
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    # xxd is part of vim-common on RHEL
    install_pkgs vim-common sleuthkit
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs xxd sleuthkit foremost
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs xxd sleuthkit
fi

log "Analysis tools installed."

# =========================================================================
# 4. YARA (with community rules if script available)
# =========================================================================
section "YARA"
log "Installing YARA..."

install_pkgs yara

YARA_SCRIPT="$SCRIPT_DIR/dependencies/yaraConfigure.sh"
if [[ -f "$YARA_SCRIPT" ]]; then
    log "Running YARA community rules builder..."
    chmod +x "$YARA_SCRIPT"
    bash "$YARA_SCRIPT" || warn "YARA rules setup had errors (non-fatal)"
else
    log "YARA installed (no community rules script found at $YARA_SCRIPT)"
fi

# =========================================================================
# 5. PYTHON3 + VOLATILITY3
# =========================================================================
section "PYTHON3 & VOLATILITY3"
log "Installing Python3 and Volatility3..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs python3 python3-pip python3-venv
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs python3 python3-pip
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs python python-pip
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs python3 py3-pip
fi

if command_exists pip3; then
    log "Installing Volatility3 via pip..."
    pip3 install --break-system-packages volatility3 2>/dev/null || \
        pip3 install volatility3 2>/dev/null || \
        warn "Volatility3 pip install failed (non-fatal)"
elif command_exists pip; then
    pip install --break-system-packages volatility3 2>/dev/null || \
        pip install volatility3 2>/dev/null || \
        warn "Volatility3 pip install failed (non-fatal)"
else
    warn "pip not available, skipping Volatility3"
fi

# =========================================================================
# 6. AVML (Azure Virtual Machine Live memory acquisition)
# =========================================================================
section "AVML"
log "Installing AVML memory acquisition tool..."

if [[ ! -f /usr/local/bin/avml ]]; then
    AVML_URL="https://github.com/microsoft/avml/releases/latest/download/avml"
    AVML_VENDOR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../vendor/avml/avml"
    if wget -q -O /tmp/avml "$AVML_URL" 2>/dev/null; then
        mv /tmp/avml /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed to /usr/local/bin/avml"
    elif [[ -f "$AVML_VENDOR" ]]; then
        cp "$AVML_VENDOR" /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed from vendored local copy"
    else
        warn "AVML download failed and no vendor copy found (non-fatal, may need manual install)"
    fi
else
    log "AVML already installed."
fi

# =========================================================================
# 7. DOCKER
# =========================================================================
section "DOCKER"

if command_exists docker; then
    log "Docker is already installed. Skipping."
else
    log "Installing Docker and Docker Compose..."

    if [[ "$PKG" == "apt" ]]; then
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        apt-get install -y ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        # Use distro ID (ubuntu or debian) for correct Docker repo
        docker_distro="$DISTRO_ID"
        [[ "$docker_distro" == "debian" || "$docker_distro" == "ubuntu" ]] || docker_distro="ubuntu"
        curl -fsSL "https://download.docker.com/linux/${docker_distro}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${docker_distro} \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update -y
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
        docker_cmd="$PKG"
        $docker_cmd remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine 2>/dev/null || true
        $docker_cmd install -y dnf-plugins-core yum-utils 2>/dev/null || true

        case "${DISTRO_ID}" in
            fedora) DOCKER_REPO_URL="https://download.docker.com/linux/fedora/docker-ce.repo" ;;
            *)      DOCKER_REPO_URL="https://download.docker.com/linux/centos/docker-ce.repo" ;;
        esac

        if command_exists dnf; then
            dnf config-manager --add-repo "$DOCKER_REPO_URL" 2>/dev/null || \
            dnf config-manager addrepo --from-repofile="$DOCKER_REPO_URL" 2>/dev/null || true
        else
            yum-config-manager --add-repo "$DOCKER_REPO_URL"
        fi
        $docker_cmd install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    elif [[ "$PKG" == "pacman" ]]; then
        pacman -S --noconfirm docker docker-compose

    elif [[ "$PKG" == "apk" ]]; then
        apk add docker docker-compose
    fi
fi

# Post-install Docker config
if command_exists systemctl && command_exists docker; then
    systemctl start docker 2>/dev/null || true
    systemctl enable docker 2>/dev/null || true
fi

if getent group docker > /dev/null 2>&1; then
    usermod -aG docker "$(whoami)" 2>/dev/null || true
    [[ -n "${SUDO_USER:-}" ]] && usermod -aG docker "$SUDO_USER" 2>/dev/null || true
fi

log "Docker installation stage done."

# =========================================================================
# 8. ANSIBLE
# =========================================================================
section "ANSIBLE"

if command_exists ansible; then
    log "Ansible is already installed. Skipping."
else
    log "Installing Ansible..."
    if [[ "$PKG" == "apt" ]]; then
        apt-get install -y software-properties-common
        add-apt-repository --yes --update ppa:ansible/ansible 2>/dev/null || true
        apt-get update -y
        apt-get install -y ansible
    elif [[ "$PKG" == "dnf" ]]; then
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y ansible-core
    elif [[ "$PKG" == "yum" ]]; then
        yum install -y epel-release
        yum install -y ansible-core
    elif [[ "$PKG" == "pacman" ]]; then
        pacman -S --noconfirm ansible
    elif [[ "$PKG" == "apk" ]]; then
        apk add ansible
    fi
fi

log "Ansible installation stage done."

# =========================================================================
# SUMMARY
# =========================================================================
section "INSTALLATION COMPLETE"
echo ""
echo "Installed tool categories:"
echo "  Essential:  net-tools, lsof, strace, tcpdump, procps, psmisc, iproute, binutils, file, acl, attr"
echo "  Security:   chkrootkit, rkhunter, clamav, auditd, sysstat, unhide"
echo "  Analysis:   xxd, sleuthkit, foremost (Debian only)"
echo "  YARA:       yara + community rules (if yaraConfigure.sh found)"
echo "  Memory:     volatility3, avml"
echo "  Infra:      docker, ansible"
echo ""

if [[ -f "$AUDITD_SCRIPT" ]]; then
    echo "Auditd:  Custom audit rules loaded from postHardenTools/dependencies/auditdSetup.sh"
else
    echo "Auditd:  Installed with default rules (custom rules not found)"
fi

if [[ -f "$YARA_SCRIPT" ]]; then
    echo "YARA:    Community rules built from postHardenTools/dependencies/yaraConfigure.sh"
else
    echo "YARA:    Installed without community rules (script not found)"
fi

echo ""
echo -e "${GREEN}All tools installed successfully!${NC}"
