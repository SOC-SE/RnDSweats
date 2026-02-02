#!/usr/bin/env bash
set -euo pipefail
# ==============================================================================
# Script Name: normalizeToolsGeneral.sh
# Description: Installs general-purpose infrastructure tools across all supported
#              Linux distributions: essential CLI tools, Docker, Ansible, Python3.
#
# Author: Samuel Brucker 2025-2026
# Version: 4.0
#
# Supported Systems:
#   - Ubuntu/Debian (apt)
#   - Fedora/RHEL/Oracle/Rocky/Alma (dnf/yum)
#   - Arch (pacman)
#   - Alpine (apk)
#
# Usage:
#   sudo ./normalizeToolsGeneral.sh
#
# ==============================================================================

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# --- Configuration ---

# Colors (disabled when not a TTY)
if [[ -t 1 ]]; then
    BLUE='\033[0;34m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    BLUE='' GREEN='' YELLOW='' RED='' NC=''
fi

log()     { echo -e "${GREEN}[INFO]${NC} ${1:-}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} ${1:-}"; }
err()     { echo -e "${RED}[ERROR]${NC} ${1:-}"; }
section() { echo -e "\n${BLUE}========== ${1:-} ==========${NC}"; }

command_exists() { command -v "$1" > /dev/null 2>&1; }

FAIL_COUNT=0

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

# Helper: install packages by distro (logs stderr, tracks failures)
install_pkgs() {
    local rc=0
    case "$PKG" in
        apt)    apt-get install -y "$@" 2>&1 || rc=$? ;;
        dnf)    dnf install -y "$@" 2>&1 || rc=$? ;;
        yum)    yum install -y "$@" 2>&1 || rc=$? ;;
        pacman) pacman -S --noconfirm "$@" 2>&1 || rc=$? ;;
        apk)    apk add "$@" 2>&1 || rc=$? ;;
    esac
    if [[ $rc -ne 0 ]]; then
        warn "Package install returned exit code $rc for: $*"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
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
# 2. PYTHON3
# =========================================================================
section "PYTHON3"
log "Installing Python3 and pip..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs python3 python3-pip python3-venv
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs python3 python3-pip
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs python python-pip
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs python3 py3-pip
fi

log "Python3 installation stage done."

# =========================================================================
# 3. DOCKER
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

        # Map derivative codenames to parent release codenames
        docker_codename="${VERSION_CODENAME:-}"
        case "$DISTRO_ID" in
            linuxmint|pop|elementary|zorin|neon)
                # These are Ubuntu derivatives; map to the Ubuntu base codename
                if [[ -n "${UBUNTU_CODENAME:-}" ]]; then
                    docker_codename="$UBUNTU_CODENAME"
                fi
                docker_distro="ubuntu"
                ;;
            kali|parrot)
                # Debian derivatives without VERSION_CODENAME matching a Docker repo
                docker_codename="bookworm"
                docker_distro="debian"
                ;;
        esac

        curl -fsSL "https://download.docker.com/linux/${docker_distro}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${docker_distro} ${docker_codename} stable" \
            | tee /etc/apt/sources.list.d/docker.list > /dev/null
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
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG docker "$SUDO_USER" 2>/dev/null || true
    fi
fi

log "Docker installation stage done."

# =========================================================================
# 4. ANSIBLE
# =========================================================================
section "ANSIBLE"

if command_exists ansible; then
    log "Ansible is already installed. Skipping."
else
    log "Installing Ansible..."
    if [[ "$PKG" == "apt" ]]; then
        if [[ "$DISTRO_ID" == "ubuntu" ]]; then
            apt-get install -y software-properties-common
            add-apt-repository --yes --update ppa:ansible/ansible 2>/dev/null || true
            apt-get update -y
        fi
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
# POST-INSTALL VERIFICATION
# =========================================================================
section "VERIFICATION"

MISSING=()
for tool in curl git vim wget jq python3 docker ansible; do
    if ! command_exists "$tool"; then
        MISSING+=("$tool")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "The following tools were not found after install: ${MISSING[*]}"
else
    log "All critical general tools verified."
fi

# =========================================================================
# SUMMARY
# =========================================================================
section "INSTALLATION COMPLETE"
echo ""
echo "Installed tool categories:"
echo "  Essential:  coreutils, net-tools, lsof, strace, tcpdump, procps, psmisc, iproute, binutils, file, acl, attr"
echo "  Python:     python3, pip"
echo "  Infra:      docker, docker-compose, ansible"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    warn "$FAIL_COUNT package install step(s) had errors (see warnings above)."
else
    log "All packages installed without errors."
fi
