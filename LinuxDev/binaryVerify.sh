#!/bin/bash
# ==============================================================================
# Script Name: binaryVerify.sh
# Description: Verify integrity of critical system binaries using package manager
#              checksums. Detects trojanized binaries that have been modified.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./binaryVerify.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -a, --all        Check all installed packages (slow)
#   -q, --quiet      Only show failures
#   -v, --verbose    Show all check details
#   -f, --fix        Attempt to reinstall modified packages
#
# What Gets Checked:
#   - sudo, passwd, su, login, sshd (authentication)
#   - ps, ls, netstat, ss, top (process/network utilities)
#   - bash, sh (shells)
#   - PAM modules (libpam)
#   - cron, systemd binaries
#
# Supported Systems:
#   - Ubuntu/Debian (dpkg)
#   - Fedora/RHEL/Rocky/Oracle (rpm)
#
# Exit Codes:
#   0 - All binaries verified
#   1 - Modified binaries detected
#   2 - Error during verification
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
CHECK_ALL=false
QUIET=false
VERBOSE=false
FIX_MODE=false
MODIFIED_COUNT=0

# Critical binaries to check
CRITICAL_BINARIES=(
    "sudo"
    "passwd"
    "su"
    "login"
    "sshd"
    "ssh"
    "ps"
    "ls"
    "netstat"
    "ss"
    "top"
    "bash"
    "sh"
    "cron"
    "crond"
    "systemctl"
    "journalctl"
    "useradd"
    "userdel"
    "usermod"
    "groupadd"
    "chpasswd"
    "cat"
    "grep"
    "find"
    "awk"
    "sed"
    "curl"
    "wget"
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

alert() {
    echo -e "${RED}[ALERT]${NC} $1"
}

debug() {
    [[ "$VERBOSE" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for full verification"
        exit 2
    fi
}

detect_package_manager() {
    if command -v dpkg &>/dev/null; then
        echo "dpkg"
    elif command -v rpm &>/dev/null; then
        echo "rpm"
    else
        echo "unknown"
    fi
}

# Get package that owns a binary (Debian)
get_package_dpkg() {
    local binary_path="$1"
    dpkg -S "$binary_path" 2>/dev/null | cut -d: -f1 | head -1
}

# Get package that owns a binary (RHEL)
get_package_rpm() {
    local binary_path="$1"
    rpm -qf "$binary_path" 2>/dev/null
}

# Verify using dpkg
verify_dpkg() {
    local packages="$1"
    local results

    # dpkg --verify returns:
    # ??5?????? c /path/to/file
    # Where 5 means MD5 checksum mismatch
    results=$(dpkg --verify $packages 2>/dev/null | grep -E "^..5" || true)
    echo "$results"
}

# Verify using rpm
verify_rpm() {
    local packages="$1"
    local results

    # rpm -V returns:
    # S.5....T.  /path/to/file
    # Where 5 means MD5 checksum mismatch, S means size changed
    results=$(rpm -V $packages 2>/dev/null | grep -E "^..5|^S" || true)
    echo "$results"
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -a|--all)
            CHECK_ALL=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--fix)
            FIX_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---
check_root

echo "========================================"
echo "BINARY INTEGRITY VERIFICATION"
echo "Time: $(date)"
echo "========================================"
echo ""

PKG_MANAGER=$(detect_package_manager)
log "Detected package manager: $PKG_MANAGER"

if [[ "$PKG_MANAGER" == "unknown" ]]; then
    error "No supported package manager found (dpkg or rpm required)"
    exit 2
fi

# Build list of packages to verify
PACKAGES_TO_CHECK=""
BINARIES_FOUND=0

log "Locating critical binaries..."
echo ""

for binary in "${CRITICAL_BINARIES[@]}"; do
    binary_path=$(command -v "$binary" 2>/dev/null)

    if [[ -n "$binary_path" ]]; then
        debug "Found: $binary -> $binary_path"
        ((BINARIES_FOUND++))

        if [[ "$PKG_MANAGER" == "dpkg" ]]; then
            pkg=$(get_package_dpkg "$binary_path")
        else
            pkg=$(get_package_rpm "$binary_path")
        fi

        if [[ -n "$pkg" ]]; then
            # Avoid duplicates
            if [[ ! " $PACKAGES_TO_CHECK " =~ " $pkg " ]]; then
                PACKAGES_TO_CHECK="$PACKAGES_TO_CHECK $pkg"
                debug "  Package: $pkg"
            fi
        else
            warn "Cannot determine package for: $binary_path"
        fi
    else
        debug "Not found: $binary"
    fi
done

# Add PAM packages
if [[ "$PKG_MANAGER" == "dpkg" ]]; then
    PACKAGES_TO_CHECK="$PACKAGES_TO_CHECK libpam-modules libpam-runtime"
else
    PACKAGES_TO_CHECK="$PACKAGES_TO_CHECK pam"
fi

# Remove leading/trailing whitespace
PACKAGES_TO_CHECK=$(echo "$PACKAGES_TO_CHECK" | xargs)

log "Found $BINARIES_FOUND critical binaries"
log "Checking ${#PACKAGES_TO_CHECK} packages: $PACKAGES_TO_CHECK"
echo ""

# Perform verification
echo "========================================"
echo "VERIFICATION RESULTS"
echo "========================================"
echo ""

if [[ "$PKG_MANAGER" == "dpkg" ]]; then
    results=$(verify_dpkg "$PACKAGES_TO_CHECK")
else
    results=$(verify_rpm "$PACKAGES_TO_CHECK")
fi

if [[ -n "$results" ]]; then
    alert "MODIFIED BINARIES DETECTED!"
    echo ""
    echo "$results" | while IFS= read -r line; do
        echo -e "${RED}  [MODIFIED]${NC} $line"
        ((MODIFIED_COUNT++))
    done
    echo ""

    # Extract list of modified files for reporting
    MODIFIED_FILES=$(echo "$results" | awk '{print $NF}')

    echo "========================================"
    echo "DETAILED ANALYSIS"
    echo "========================================"
    echo ""

    for file in $MODIFIED_FILES; do
        if [[ -f "$file" ]]; then
            echo -e "${YELLOW}File:${NC} $file"
            echo "  Size: $(stat -c%s "$file" 2>/dev/null || echo "unknown") bytes"
            echo "  Modified: $(stat -c%y "$file" 2>/dev/null || echo "unknown")"
            echo "  SHA256: $(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "unknown")"

            # Check if binary is stripped or has debug symbols
            if file "$file" | grep -q "not stripped"; then
                echo -e "  ${YELLOW}Warning: Binary is not stripped (unusual for system binary)${NC}"
            fi

            # Check for suspicious strings
            if strings "$file" 2>/dev/null | grep -qiE "reverse|shell|backdoor|hack|pwn"; then
                echo -e "  ${RED}ALERT: Suspicious strings found in binary!${NC}"
            fi
            echo ""
        fi
    done

    if [[ "$FIX_MODE" == "true" ]]; then
        echo "========================================"
        echo "ATTEMPTING REPAIR"
        echo "========================================"
        echo ""

        # Get unique packages from modified files
        PACKAGES_TO_REINSTALL=""
        for file in $MODIFIED_FILES; do
            if [[ "$PKG_MANAGER" == "dpkg" ]]; then
                pkg=$(get_package_dpkg "$file")
            else
                pkg=$(get_package_rpm "$file")
            fi
            if [[ -n "$pkg" && ! " $PACKAGES_TO_REINSTALL " =~ " $pkg " ]]; then
                PACKAGES_TO_REINSTALL="$PACKAGES_TO_REINSTALL $pkg"
            fi
        done

        log "Reinstalling packages: $PACKAGES_TO_REINSTALL"

        if [[ "$PKG_MANAGER" == "dpkg" ]]; then
            apt-get install --reinstall -y $PACKAGES_TO_REINSTALL
        else
            yum reinstall -y $PACKAGES_TO_REINSTALL || dnf reinstall -y $PACKAGES_TO_REINSTALL
        fi

        log "Reinstallation complete. Re-running verification..."
        echo ""

        # Re-verify
        results=$(verify_dpkg "$PACKAGES_TO_CHECK" 2>/dev/null || verify_rpm "$PACKAGES_TO_CHECK" 2>/dev/null)
        if [[ -z "$results" ]]; then
            echo -e "${GREEN}All binaries now verified successfully!${NC}"
        else
            error "Some binaries still modified after reinstall - possible rootkit!"
        fi
    fi

    echo ""
    echo "========================================"
    echo "RECOMMENDATIONS"
    echo "========================================"
    echo ""
    echo "1. Investigate the modified binaries immediately"
    echo "2. Compare with known-good copies from another system"
    echo "3. Check for rootkits: rkhunter --check"
    echo "4. Review system logs for unauthorized access"
    echo "5. Consider reimaging the system if compromise is confirmed"
    echo ""
    echo "To reinstall modified packages, run:"
    echo "  $0 --fix"

    exit 1
else
    echo -e "${GREEN}All critical binaries verified successfully!${NC}"
    echo ""
    echo "Checked packages:"
    for pkg in $PACKAGES_TO_CHECK; do
        echo -e "  ${GREEN}[OK]${NC} $pkg"
    done
    exit 0
fi
