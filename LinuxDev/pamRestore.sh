#!/bin/bash
# ==============================================================================
# Script Name: pamRestore.sh
# Description: Emergency PAM recovery by reinstalling all PAM-related packages
#              from the package manager. Use this after confirmed PAM compromise.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./pamRestore.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -n, --dry-run    Show what would be reinstalled without doing it
#   -f, --force      Skip confirmation prompt
#   -b, --backup     Backup current PAM configs before restore
#
# WARNING:
#   This will reset ALL PAM configuration to defaults!
#   Any custom PAM configurations will be lost.
#   Only use this after confirming PAM has been compromised.
#
# Supported Systems:
#   - Ubuntu/Debian (apt)
#   - Fedora/RHEL/Rocky/Alma (dnf/yum)
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - Aborted by user
#   3 - Unsupported OS
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
DRY_RUN=false
FORCE=false
BACKUP=false
BACKUP_DIR="/root/pam_backup_$(date +%Y%m%d_%H%M%S)"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -35 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
        OS_FAMILY=""
        case "$ID" in
            ubuntu|debian|mint|pop|kali)
                OS_FAMILY="debian"
                ;;
            fedora|rhel|centos|rocky|alma|ol|oracle)
                OS_FAMILY="rhel"
                ;;
            *)
                OS_FAMILY="unknown"
                ;;
        esac
    else
        error "Cannot detect OS"
        exit 3
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -b|--backup)
            BACKUP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Functions ---
backup_pam_configs() {
    log "Backing up current PAM configuration to $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/pam.d "$BACKUP_DIR/"
    cp -a /etc/pam.conf "$BACKUP_DIR/" 2>/dev/null || true

    # Also backup PAM modules
    mkdir -p "$BACKUP_DIR/modules"
    find /lib /lib64 /usr/lib /usr/lib64 -name "pam_*.so" -exec cp {} "$BACKUP_DIR/modules/" \; 2>/dev/null

    chmod -R 600 "$BACKUP_DIR"
    log "Backup complete: $BACKUP_DIR"
}

restore_debian() {
    log "Detected Debian/Ubuntu family"

    # Find all packages that own files in /etc/pam.d/
    log "Finding packages that own PAM configuration files..."
    local pam_packages
    pam_packages=$(dpkg -S /etc/pam.d/* 2>/dev/null | cut -d: -f1 | sort -u | tr '\n' ' ')

    if [[ -z "$pam_packages" ]]; then
        warn "No packages found owning /etc/pam.d/ files, using defaults"
        pam_packages="libpam-modules libpam-runtime login passwd"
    fi

    log "PAM-related packages: $pam_packages"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo ""
        echo -e "${BLUE}[DRY-RUN] Would run:${NC}"
        echo "  apt-get install --reinstall -o Dpkg::Options::=\"--force-confask,confnew,confmiss\" $pam_packages"
        echo "  apt-get install --reinstall -y libpam-modules libpam-runtime"
        return
    fi

    log "Reinstalling PAM packages with config reset..."

    # Reinstall with force new config options
    DEBIAN_FRONTEND=noninteractive apt-get install --reinstall \
        -o Dpkg::Options::="--force-confask" \
        -o Dpkg::Options::="--force-confnew" \
        -o Dpkg::Options::="--force-confmiss" \
        -y $pam_packages

    # Also reinstall core PAM modules
    DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
        libpam-modules \
        libpam-modules-bin \
        libpam-runtime \
        libpam0g

    log "PAM packages reinstalled"
}

restore_rhel() {
    log "Detected RHEL/Fedora family"

    # Find all packages that own files in /etc/pam.d/
    log "Finding packages that own PAM configuration files..."
    local pam_packages
    pam_packages=$(rpm -qf /etc/pam.d/* 2>/dev/null | sort -u | grep -v "not owned" | tr '\n' ' ')

    if [[ -z "$pam_packages" ]]; then
        warn "No packages found owning /etc/pam.d/ files, using defaults"
        pam_packages="pam"
    fi

    log "PAM-related packages: $pam_packages"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo ""
        echo -e "${BLUE}[DRY-RUN] Would run:${NC}"
        if command -v dnf &>/dev/null; then
            echo "  dnf reinstall -y $pam_packages"
            echo "  dnf reinstall -y pam"
        else
            echo "  yum reinstall -y $pam_packages"
            echo "  yum reinstall -y pam"
        fi
        return
    fi

    log "Reinstalling PAM packages..."

    if command -v dnf &>/dev/null; then
        dnf reinstall -y $pam_packages
        dnf reinstall -y pam pam-devel 2>/dev/null || true
    else
        yum reinstall -y $pam_packages
        yum reinstall -y pam pam-devel 2>/dev/null || true
    fi

    log "PAM packages reinstalled"
}

verify_pam() {
    log "Verifying PAM installation..."

    local errors=0

    # Check critical PAM modules exist and are valid ELF
    for mod in pam_unix.so pam_deny.so pam_permit.so; do
        local mod_path
        mod_path=$(find /lib /lib64 /usr/lib /usr/lib64 -name "$mod" 2>/dev/null | head -1)

        if [[ -z "$mod_path" ]]; then
            error "Critical PAM module missing: $mod"
            ((errors++))
        elif ! file "$mod_path" | grep -q "ELF"; then
            error "PAM module is not valid ELF binary: $mod_path"
            ((errors++))
        else
            log "Verified: $mod_path"
        fi
    done

    # Check /etc/pam.d exists and has files
    if [[ ! -d /etc/pam.d ]]; then
        error "/etc/pam.d directory missing!"
        ((errors++))
    else
        local pam_files
        pam_files=$(ls /etc/pam.d/ 2>/dev/null | wc -l)
        if [[ $pam_files -lt 5 ]]; then
            error "/etc/pam.d has very few files ($pam_files) - may be incomplete"
            ((errors++))
        else
            log "/etc/pam.d contains $pam_files configuration files"
        fi
    fi

    # Test PAM is working by checking su
    if command -v pamtester &>/dev/null; then
        log "Testing PAM with pamtester..."
        if pamtester login root authenticate 2>/dev/null; then
            log "PAM authentication test passed"
        else
            warn "PAM authentication test failed (may be normal)"
        fi
    fi

    if [[ $errors -gt 0 ]]; then
        error "PAM verification found $errors errors"
        return 1
    else
        log "PAM verification passed"
        return 0
    fi
}

# --- Main Execution ---
check_root
detect_os

echo "========================================"
echo "PAM RESTORE - $(hostname)"
echo "Time: $(date)"
echo "OS: $OS_ID ($OS_FAMILY)"
echo "========================================"

if [[ "$OS_FAMILY" == "unknown" ]]; then
    error "Unsupported operating system: $OS_ID"
    exit 3
fi

# Warning
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                         WARNING                              ║${NC}"
echo -e "${RED}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${RED}║  This will RESET all PAM configuration to system defaults!  ║${NC}"
echo -e "${RED}║  Any custom PAM configurations will be LOST!                ║${NC}"
echo -e "${RED}║                                                              ║${NC}"
echo -e "${RED}║  Only use this if you have confirmed PAM compromise.        ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${BLUE}>>> DRY RUN MODE - No changes will be made <<<${NC}"
    echo ""
fi

# Confirmation
if [[ "$DRY_RUN" == "false" && "$FORCE" == "false" ]]; then
    read -p "Type 'RESTORE PAM' to confirm: " confirm
    if [[ "$confirm" != "RESTORE PAM" ]]; then
        echo "Aborted."
        exit 2
    fi
fi

# Backup if requested
if [[ "$BACKUP" == "true" && "$DRY_RUN" == "false" ]]; then
    backup_pam_configs
fi

# Perform restoration
case "$OS_FAMILY" in
    debian)
        restore_debian
        ;;
    rhel)
        restore_rhel
        ;;
esac

# Verify (unless dry run)
if [[ "$DRY_RUN" == "false" ]]; then
    echo ""
    verify_pam
fi

echo ""
echo "========================================"
echo "PAM RESTORE COMPLETE"
echo "========================================"

if [[ "$BACKUP" == "true" && "$DRY_RUN" == "false" ]]; then
    echo "Backup location: $BACKUP_DIR"
fi

if [[ "$DRY_RUN" == "false" ]]; then
    echo ""
    echo -e "${YELLOW}IMPORTANT: Test authentication before logging out!${NC}"
    echo -e "${YELLOW}Open a new SSH session to verify login still works.${NC}"
fi

exit 0
