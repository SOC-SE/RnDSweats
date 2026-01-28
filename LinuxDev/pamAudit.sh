#!/bin/bash
# ==============================================================================
# Script Name: pamAudit.sh
# Description: Comprehensive PAM (Pluggable Authentication Modules) security
#              audit. Detects misconfigurations, backdoors, and weaknesses.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./pamAudit.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -v, --verbose    Show detailed output
#   -f, --fix        Attempt to fix common issues (creates backups)
#   -q, --quiet      Only show critical issues
#
# What Gets Checked:
#   - NULL/empty passwords allowed (nullok)
#   - pam_permit.so backdoors (unconditional access)
#   - Password hashing strength (MD5 vs SHA512)
#   - Password quality enforcement (pwquality/cracklib)
#   - Account lockout (faillock/tally2)
#   - Sudo PAM configuration
#   - SSH PAM configuration
#   - Suspicious/unknown PAM modules
#   - PAM module file integrity
#
# Supported Systems:
#   - Ubuntu/Debian
#   - Fedora/RHEL/Rocky/Oracle
#
# Exit Codes:
#   0 - No critical issues found
#   1 - Critical issues detected
#   2 - Error during audit
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
VERBOSE=false
FIX_MODE=false
QUIET=false
ISSUES_FOUND=0
CRITICAL_ISSUES=0
WARNINGS=0

# PAM directories
PAM_DIR="/etc/pam.d"
PAM_SECURITY_DIR="/etc/security"

# Known legitimate PAM modules
KNOWN_MODULES=(
    "pam_unix.so"
    "pam_deny.so"
    "pam_permit.so"
    "pam_env.so"
    "pam_faillock.so"
    "pam_faildelay.so"
    "pam_limits.so"
    "pam_loginuid.so"
    "pam_namespace.so"
    "pam_nologin.so"
    "pam_pwquality.so"
    "pam_cracklib.so"
    "pam_securetty.so"
    "pam_selinux.so"
    "pam_sepermit.so"
    "pam_shells.so"
    "pam_succeed_if.so"
    "pam_systemd.so"
    "pam_tally2.so"
    "pam_time.so"
    "pam_umask.so"
    "pam_userdb.so"
    "pam_warn.so"
    "pam_wheel.so"
    "pam_xauth.so"
    "pam_access.so"
    "pam_cap.so"
    "pam_debug.so"
    "pam_echo.so"
    "pam_exec.so"
    "pam_filter.so"
    "pam_ftp.so"
    "pam_group.so"
    "pam_issue.so"
    "pam_keyinit.so"
    "pam_lastlog.so"
    "pam_listfile.so"
    "pam_localuser.so"
    "pam_mail.so"
    "pam_mkhomedir.so"
    "pam_motd.so"
    "pam_rootok.so"
    "pam_timestamp.so"
    "pam_tty_audit.so"
    "pam_usertype.so"
    "pam_sss.so"
    "pam_ldap.so"
    "pam_krb5.so"
    "pam_winbind.so"
    "pam_gnome_keyring.so"
    "pam_kwallet5.so"
    "pam_fprintd.so"
    "pam_google_authenticator.so"
    "pam_u2f.so"
    "pam_yubico.so"
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# --- Helper Functions ---
usage() {
    head -50 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
    ((ISSUES_FOUND++))
}

critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    ((CRITICAL_ISSUES++))
    ((ISSUES_FOUND++))
}

ok() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[OK]${NC} $1"
}

debug() {
    [[ "$VERBOSE" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[WARN]${NC} Running without root - some checks may be incomplete"
    fi
}

# Check if a line exists in a PAM file
check_pam_line() {
    local file="$1"
    local pattern="$2"
    grep -qE "$pattern" "$file" 2>/dev/null
}

# Check if a module is known
is_known_module() {
    local module="$1"
    for known in "${KNOWN_MODULES[@]}"; do
        if [[ "$module" == "$known" ]]; then
            return 0
        fi
    done
    return 1
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--fix)
            FIX_MODE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
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
echo "PAM SECURITY AUDIT"
echo "Time: $(date)"
echo "========================================"
echo ""

# Detect OS
if [[ -f /etc/redhat-release ]]; then
    OS_FAMILY="rhel"
    log "Detected RHEL-based system"
    AUTH_FILE="$PAM_DIR/system-auth"
    PASSWORD_FILE="$PAM_DIR/system-auth"
else
    OS_FAMILY="debian"
    log "Detected Debian-based system"
    AUTH_FILE="$PAM_DIR/common-auth"
    PASSWORD_FILE="$PAM_DIR/common-password"
fi
echo ""

# ==============================================================================
# CHECK 1: NULL Passwords (nullok)
# ==============================================================================
echo -e "${BOLD}[CHECK 1] NULL Passwords (nullok)${NC}"

NULLOK_FILES=$(grep -l "nullok" "$PAM_DIR"/* 2>/dev/null || true)
if [[ -n "$NULLOK_FILES" ]]; then
    critical "nullok found - allows blank passwords!"
    for file in $NULLOK_FILES; do
        echo "  File: $file"
        grep "nullok" "$file" | while read -r line; do
            echo "    $line"
        done
    done
    echo ""
    if [[ "$FIX_MODE" == "true" ]]; then
        for file in $NULLOK_FILES; do
            cp "$file" "${file}.bak.$(date +%s)"
            sed -i 's/nullok//g' "$file"
            log "Removed nullok from $file (backup created)"
        done
    else
        echo "  Fix: Remove 'nullok' from PAM configuration"
    fi
else
    ok "No nullok found - blank passwords not allowed"
fi
echo ""

# ==============================================================================
# CHECK 2: pam_permit.so Backdoors
# ==============================================================================
echo -e "${BOLD}[CHECK 2] pam_permit.so Backdoors${NC}"

# Check for pam_permit in auth or password contexts (very dangerous)
PERMIT_BACKDOORS=false

for pam_file in "$PAM_DIR"/*; do
    [[ ! -f "$pam_file" ]] && continue

    # Check for pam_permit.so with 'sufficient' (instant success = backdoor)
    if grep -qE "^(auth|password).*sufficient.*pam_permit\.so" "$pam_file" 2>/dev/null; then
        critical "pam_permit.so BACKDOOR in $pam_file!"
        grep -E "^(auth|password).*sufficient.*pam_permit\.so" "$pam_file"
        PERMIT_BACKDOORS=true
    fi

    # Check for pam_permit.so as the only auth method
    if grep -qE "^auth.*required.*pam_permit\.so" "$pam_file" 2>/dev/null; then
        if ! grep -qE "^auth.*(pam_unix|pam_sss|pam_ldap|pam_krb5)" "$pam_file" 2>/dev/null; then
            critical "pam_permit.so is ONLY auth in $pam_file - BACKDOOR!"
            PERMIT_BACKDOORS=true
        fi
    fi
done

if [[ "$PERMIT_BACKDOORS" == "false" ]]; then
    ok "No pam_permit.so backdoors detected"
fi
echo ""

# ==============================================================================
# CHECK 3: Password Hashing Strength
# ==============================================================================
echo -e "${BOLD}[CHECK 3] Password Hashing Strength${NC}"

if [[ -f "$PASSWORD_FILE" ]]; then
    if grep -qE "pam_unix\.so.*md5" "$PASSWORD_FILE" 2>/dev/null; then
        critical "MD5 password hashing detected - WEAK!"
        echo "  MD5 hashes can be cracked in seconds"
        if [[ "$FIX_MODE" == "true" ]]; then
            cp "$PASSWORD_FILE" "${PASSWORD_FILE}.bak.$(date +%s)"
            sed -i 's/md5/sha512/g' "$PASSWORD_FILE"
            log "Changed md5 to sha512 in $PASSWORD_FILE"
        fi
    elif grep -qE "pam_unix\.so.*sha256" "$PASSWORD_FILE" 2>/dev/null; then
        warn "SHA256 hashing detected - SHA512 recommended"
    elif grep -qE "pam_unix\.so.*sha512" "$PASSWORD_FILE" 2>/dev/null; then
        ok "SHA512 password hashing in use"
    else
        warn "Cannot determine password hashing algorithm"
        debug "Check: grep pam_unix $PASSWORD_FILE"
    fi
else
    warn "Password PAM file not found: $PASSWORD_FILE"
fi
echo ""

# ==============================================================================
# CHECK 4: Password Quality Enforcement
# ==============================================================================
echo -e "${BOLD}[CHECK 4] Password Quality Enforcement${NC}"

if [[ -f "$PASSWORD_FILE" ]]; then
    if grep -qE "pam_pwquality\.so|pam_cracklib\.so" "$PASSWORD_FILE" 2>/dev/null; then
        ok "Password quality module enabled (pwquality/cracklib)"

        # Check pwquality.conf for settings
        if [[ -f "$PAM_SECURITY_DIR/pwquality.conf" ]]; then
            debug "Checking $PAM_SECURITY_DIR/pwquality.conf"
            minlen=$(grep -E "^minlen" "$PAM_SECURITY_DIR/pwquality.conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
            if [[ -n "$minlen" && "$minlen" -lt 12 ]]; then
                warn "Minimum password length is $minlen (recommend 12+)"
            fi
        fi
    else
        warn "No password quality enforcement (pam_pwquality/pam_cracklib)"
        echo "  Weak passwords may be allowed"
        if [[ "$FIX_MODE" == "true" ]]; then
            echo "  Manual fix required - add pam_pwquality.so to $PASSWORD_FILE"
        fi
    fi
else
    warn "Password PAM file not found"
fi
echo ""

# ==============================================================================
# CHECK 5: Account Lockout Protection
# ==============================================================================
echo -e "${BOLD}[CHECK 5] Account Lockout (Brute-force Protection)${NC}"

LOCKOUT_FOUND=false

if [[ -f "$AUTH_FILE" ]]; then
    if grep -qE "pam_faillock\.so|pam_tally2\.so" "$AUTH_FILE" 2>/dev/null; then
        ok "Account lockout module enabled"
        LOCKOUT_FOUND=true

        # Check faillock configuration
        if grep -q "pam_faillock" "$AUTH_FILE"; then
            deny=$(grep "pam_faillock" "$AUTH_FILE" | grep -oP 'deny=\K[0-9]+' | head -1)
            if [[ -n "$deny" ]]; then
                debug "Lockout after $deny failed attempts"
            fi
        fi
    fi
fi

# Also check /etc/pam.d/login and /etc/pam.d/sshd
for check_file in "$PAM_DIR/login" "$PAM_DIR/sshd"; do
    if [[ -f "$check_file" ]]; then
        if grep -qE "pam_faillock\.so|pam_tally2\.so" "$check_file" 2>/dev/null; then
            LOCKOUT_FOUND=true
        fi
    fi
done

if [[ "$LOCKOUT_FOUND" == "false" ]]; then
    warn "No account lockout protection detected"
    echo "  System vulnerable to brute-force attacks"
fi
echo ""

# ==============================================================================
# CHECK 6: Sudo PAM Configuration
# ==============================================================================
echo -e "${BOLD}[CHECK 6] Sudo PAM Configuration${NC}"

if [[ -f "$PAM_DIR/sudo" ]]; then
    # Check for pam_permit backdoor in sudo
    if grep -qE "sufficient.*pam_permit\.so" "$PAM_DIR/sudo" 2>/dev/null; then
        critical "SUDO BACKDOOR: pam_permit.so allows passwordless sudo!"
        grep "pam_permit" "$PAM_DIR/sudo"
    else
        ok "No pam_permit backdoor in sudo config"
    fi

    # Check if password is required for sudo
    if grep -qE "auth.*pam_unix\.so|auth.*pam_sss\.so" "$PAM_DIR/sudo" 2>/dev/null; then
        ok "Password authentication required for sudo"
    elif grep -qE "pam_rootok\.so" "$PAM_DIR/sudo" 2>/dev/null; then
        debug "pam_rootok.so allows root to sudo without password (normal)"
    fi
else
    warn "Sudo PAM file not found"
fi
echo ""

# ==============================================================================
# CHECK 7: SSH PAM Configuration
# ==============================================================================
echo -e "${BOLD}[CHECK 7] SSH PAM Configuration${NC}"

if [[ -f "$PAM_DIR/sshd" ]]; then
    # Check for backdoors
    if grep -qE "sufficient.*pam_permit\.so" "$PAM_DIR/sshd" 2>/dev/null; then
        critical "SSH BACKDOOR: pam_permit.so allows passwordless SSH!"
        grep "pam_permit" "$PAM_DIR/sshd"
    else
        ok "No pam_permit backdoor in SSH config"
    fi

    # Check for suspicious exec calls
    if grep -qE "pam_exec\.so" "$PAM_DIR/sshd" 2>/dev/null; then
        warn "pam_exec.so found in SSH config - verify it's legitimate"
        grep "pam_exec" "$PAM_DIR/sshd"
    fi
else
    debug "SSH PAM file not found (SSH may not be installed)"
fi
echo ""

# ==============================================================================
# CHECK 8: Unknown/Suspicious PAM Modules
# ==============================================================================
echo -e "${BOLD}[CHECK 8] Unknown/Suspicious PAM Modules${NC}"

UNKNOWN_MODULES=()

for pam_file in "$PAM_DIR"/*; do
    [[ ! -f "$pam_file" ]] && continue

    # Extract all module names
    modules=$(grep -oP 'pam_\w+\.so' "$pam_file" 2>/dev/null | sort -u)

    for module in $modules; do
        if ! is_known_module "$module"; then
            if [[ ! " ${UNKNOWN_MODULES[*]} " =~ " $module " ]]; then
                UNKNOWN_MODULES+=("$module")
            fi
        fi
    done
done

if [[ ${#UNKNOWN_MODULES[@]} -gt 0 ]]; then
    warn "Unknown PAM modules found (verify these are legitimate):"
    for module in "${UNKNOWN_MODULES[@]}"; do
        echo "  - $module"
        # Find which files use it
        grep -l "$module" "$PAM_DIR"/* 2>/dev/null | while read -r f; do
            echo "    Used in: $f"
        done
    done
else
    ok "All PAM modules are recognized"
fi
echo ""

# ==============================================================================
# CHECK 9: PAM Module File Integrity
# ==============================================================================
echo -e "${BOLD}[CHECK 9] PAM Module File Integrity${NC}"

# Check common PAM module locations
PAM_LIB_DIRS=(
    "/lib/x86_64-linux-gnu/security"
    "/lib64/security"
    "/lib/security"
    "/usr/lib/x86_64-linux-gnu/security"
    "/usr/lib64/security"
)

for dir in "${PAM_LIB_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        debug "Checking PAM modules in $dir"

        # Check for recently modified modules (last 24 hours)
        recent_mods=$(find "$dir" -name "pam_*.so" -mtime -1 2>/dev/null)
        if [[ -n "$recent_mods" ]]; then
            warn "Recently modified PAM modules (last 24h):"
            echo "$recent_mods" | while read -r mod; do
                echo "  $mod ($(stat -c '%y' "$mod" 2>/dev/null | cut -d. -f1))"
            done
        fi

        # Check for world-writable modules
        writable=$(find "$dir" -name "pam_*.so" -perm -002 2>/dev/null)
        if [[ -n "$writable" ]]; then
            critical "World-writable PAM modules found!"
            echo "$writable"
        fi

        break  # Only check first existing directory
    fi
done

ok "PAM module integrity check complete"
echo ""

# ==============================================================================
# CHECK 10: /etc/shadow Password Verification
# ==============================================================================
echo -e "${BOLD}[CHECK 10] Shadow File Password Analysis${NC}"

if [[ -r /etc/shadow ]]; then
    # Check for empty passwords
    empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || length($2) < 3) && $2 !~ /^[!*]/ {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pass" ]]; then
        critical "Accounts with empty/no passwords:"
        echo "$empty_pass" | while read -r user; do
            echo "  - $user"
        done
    else
        ok "No accounts with empty passwords"
    fi

    # Check for weak hash types
    md5_users=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$md5_users" ]]; then
        warn "Accounts using weak MD5 password hashes:"
        echo "$md5_users" | while read -r user; do
            echo "  - $user"
        done
    fi

    sha512_count=$(awk -F: '$2 ~ /^\$6\$/ {count++} END {print count+0}' /etc/shadow 2>/dev/null)
    debug "Accounts using SHA512: $sha512_count"
else
    warn "Cannot read /etc/shadow (run as root for full audit)"
fi
echo ""

# ==============================================================================
# SUMMARY
# ==============================================================================
echo "========================================"
echo "AUDIT SUMMARY"
echo "========================================"
echo ""
echo "Total issues found:    $ISSUES_FOUND"
echo -e "Critical issues:       ${RED}$CRITICAL_ISSUES${NC}"
echo -e "Warnings:              ${YELLOW}$WARNINGS${NC}"
echo ""

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    echo -e "${RED}CRITICAL ISSUES DETECTED!${NC}"
    echo "Review and remediate critical issues immediately."
    echo ""
    echo "Quick fixes:"
    echo "  1. Remove 'nullok' from PAM configs"
    echo "  2. Remove pam_permit.so backdoors"
    echo "  3. Use SHA512 for password hashing"
    echo "  4. Enable account lockout (pam_faillock)"
    echo ""
    echo "Run with --fix to attempt automatic remediation"
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}Warnings found - review recommended${NC}"
    exit 0
else
    echo -e "${GREEN}No critical PAM issues detected${NC}"
    exit 0
fi
