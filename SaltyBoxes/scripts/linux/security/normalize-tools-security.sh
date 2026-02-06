#!/usr/bin/env bash
set -euo pipefail
# ==============================================================================
# Script Name: normalize-tools-security.sh
# Description: Installs security, forensic, and analysis tools across all
#              supported Linux distributions. Includes YARA, Volatility3, AVML,
#              and updates scanner databases (no scans are run).
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
#   sudo ./normalize-tools-security.sh
#
# ==============================================================================

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
# 1. FORENSIC / SECURITY TOOLS
# =========================================================================
section "FORENSIC & SECURITY TOOLS"
log "Installing security scanning and forensic tools..."

if [[ "$PKG" == "apt" ]]; then
    apt-get update -y
    install_pkgs chkrootkit rkhunter clamav clamav-daemon \
        auditd sysstat unhide debsums
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
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
    if command_exists auditctl && command_exists systemctl; then
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
        log "auditd enabled (no custom rules file found at $AUDITD_SCRIPT)"
    fi
fi

log "Forensic & security tools installed."

# =========================================================================
# 2. ANALYSIS TOOLS
# =========================================================================
section "ANALYSIS TOOLS"
log "Installing binary analysis and forensic analysis tools..."

if [[ "$PKG" == "apt" ]]; then
    install_pkgs xxd sleuthkit foremost
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    # xxd is part of vim-common on RHEL
    install_pkgs vim-common sleuthkit
elif [[ "$PKG" == "pacman" ]]; then
    # xxd is part of vim on Arch
    install_pkgs vim sleuthkit foremost
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs xxd sleuthkit
fi

log "Analysis tools installed."

# =========================================================================
# 3. YARA
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
# 4. VOLATILITY3 (in venv)
# =========================================================================
section "VOLATILITY3"
log "Installing Volatility3 into /opt/volatility3-venv..."

# Ensure python3-venv is available
if [[ "$PKG" == "apt" ]]; then
    install_pkgs python3 python3-pip python3-venv
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    install_pkgs python3 python3-pip
elif [[ "$PKG" == "pacman" ]]; then
    install_pkgs python python-pip
elif [[ "$PKG" == "apk" ]]; then
    install_pkgs python3 py3-pip
fi

VENV_DIR="/opt/volatility3-venv"
if command_exists python3; then
    python3 -m venv "$VENV_DIR" 2>/dev/null || warn "Failed to create venv at $VENV_DIR"
    if [[ -f "$VENV_DIR/bin/pip" ]]; then
        "$VENV_DIR/bin/pip" install --upgrade pip 2>&1 || true
        "$VENV_DIR/bin/pip" install volatility3 2>&1 || warn "Volatility3 pip install failed (non-fatal)"
        if [[ -f "$VENV_DIR/bin/vol" ]]; then
            ln -sf "$VENV_DIR/bin/vol" /usr/local/bin/vol
            log "Volatility3 installed; 'vol' linked to /usr/local/bin/vol"
        fi
    fi
else
    warn "python3 not available, skipping Volatility3"
fi

# =========================================================================
# 5. AVML
# =========================================================================
section "AVML"
log "Installing AVML memory acquisition tool..."

if [[ ! -f /usr/local/bin/avml ]]; then
    AVML_URL="https://github.com/microsoft/avml/releases/latest/download/avml"
    AVML_VENDOR="$SCRIPT_DIR/../../../../vendor/avml/avml"
    AVML_TMP="$(mktemp /tmp/avml.XXXXXXXXXX)"
    trap 'rm -f "$AVML_TMP"' EXIT
    if wget -q -O "$AVML_TMP" "$AVML_URL" 2>/dev/null; then
        mv "$AVML_TMP" /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed to /usr/local/bin/avml"
    elif [[ -f "$AVML_VENDOR" ]]; then
        rm -f "$AVML_TMP"
        cp "$AVML_VENDOR" /usr/local/bin/avml
        chmod +x /usr/local/bin/avml
        log "AVML installed from vendored local copy"
    else
        rm -f "$AVML_TMP"
        warn "AVML download failed and no vendor copy found (non-fatal, may need manual install)"
    fi
else
    log "AVML already installed."
fi

# =========================================================================
# 6. DATABASE UPDATES
# =========================================================================
section "DATABASE UPDATES"
log "Updating scanner databases (no scans)..."

if command_exists freshclam; then
    if freshclam 2>&1; then
        log "ClamAV database updated."
    else
        warn "freshclam update failed (non-fatal)"
    fi
else
    warn "freshclam not found, skipping ClamAV database update"
fi

if command_exists rkhunter; then
    rkhunter --update 2>&1 || warn "rkhunter --update failed (non-fatal, may already be current)"
    rkhunter --propupd 2>&1 || warn "rkhunter --propupd failed (non-fatal)"
    log "rkhunter file properties updated."
else
    warn "rkhunter not found, skipping database update"
fi

# =========================================================================
# POST-INSTALL VERIFICATION
# =========================================================================
section "VERIFICATION"

MISSING=()
for tool in rkhunter clamscan auditctl yara vol; do
    if ! command_exists "$tool"; then
        MISSING+=("$tool")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "The following tools were not found after install: ${MISSING[*]}"
else
    log "All critical security tools verified."
fi

# =========================================================================
# SUMMARY
# =========================================================================
section "INSTALLATION COMPLETE"
echo ""
echo "Installed tool categories:"
echo "  Security:   chkrootkit, rkhunter, clamav, auditd, sysstat, unhide"
if [[ "$PKG" == "apt" ]]; then
    echo "  Analysis:   xxd, sleuthkit, foremost"
elif [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    echo "  Analysis:   xxd (vim-common), sleuthkit"
elif [[ "$PKG" == "pacman" ]]; then
    echo "  Analysis:   xxd (vim), sleuthkit, foremost"
elif [[ "$PKG" == "apk" ]]; then
    echo "  Analysis:   xxd, sleuthkit"
fi
echo "  YARA:       yara + community rules (if yaraConfigure.sh found)"
echo "  Memory:     volatility3 (/opt/volatility3-venv), avml"
echo "  Databases:  freshclam, rkhunter --update, rkhunter --propupd"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    warn "$FAIL_COUNT package install step(s) had errors (see warnings above)."
else
    log "All packages installed without errors."
fi
