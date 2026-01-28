#!/bin/bash
# ==============================================================================
# Script Name: pamManager.sh
# Description: PAM security audit and emergency restore tool
#              Detects misconfigurations and backdoors, with restore capability
# Author: CCDC Team
# Date: 2025-2026
# Version: 2.0
#
# Usage:
#   ./pamManager.sh [action] [options]
#
# Actions:
#   audit        Audit PAM configuration for security issues (default)
#   restore      Emergency PAM restore from package manager
#
# Options:
#   -h, --help       Show this help message
#   -v, --verbose    Show detailed output
#   -f, --fix        Attempt to fix critical issues (audit mode) or skip prompt (restore mode)
#   -q, --quiet      Only show critical issues
#   -n, --dry-run    Show what would be done without making changes
#   -b, --backup     Backup current PAM configs before changes
#
# Severity Levels:
#   CRITICAL - Confirmed backdoor or severe vulnerability (e.g., pam_permit as auth)
#   WARNING  - Configuration weakness worth reviewing (e.g., no account lockout)
#   NOTE     - Common configuration that may be intentional (e.g., nullok on some files)
#
# Supported Systems:
#   - Ubuntu/Debian
#   - Fedora/RHEL/Rocky/Oracle
#
# Exit Codes:
#   0 - No critical issues found / restore successful
#   1 - Critical issues detected / restore failed
#   2 - Error or aborted
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
ACTION="audit"
VERBOSE=false
FIX_MODE=false
QUIET=false
DRY_RUN=false
BACKUP=false
ISSUES_FOUND=0
CRITICAL_ISSUES=0
WARNINGS=0
NOTES=0

PAM_DIR="/etc/pam.d"
PAM_SECURITY_DIR="/etc/security"
BACKUP_DIR="/root/pam_backup_$(date +%Y%m%d_%H%M%S)"

# Known legitimate PAM modules
KNOWN_MODULES=(
    "pam_unix.so" "pam_deny.so" "pam_permit.so" "pam_env.so"
    "pam_faillock.so" "pam_faildelay.so" "pam_limits.so" "pam_loginuid.so"
    "pam_namespace.so" "pam_nologin.so" "pam_pwquality.so" "pam_cracklib.so"
    "pam_securetty.so" "pam_selinux.so" "pam_sepermit.so" "pam_shells.so"
    "pam_succeed_if.so" "pam_systemd.so" "pam_tally2.so" "pam_time.so"
    "pam_umask.so" "pam_userdb.so" "pam_warn.so" "pam_wheel.so"
    "pam_xauth.so" "pam_access.so" "pam_cap.so" "pam_debug.so"
    "pam_echo.so" "pam_exec.so" "pam_filter.so" "pam_ftp.so"
    "pam_group.so" "pam_issue.so" "pam_keyinit.so" "pam_lastlog.so"
    "pam_listfile.so" "pam_localuser.so" "pam_mail.so" "pam_mkhomedir.so"
    "pam_motd.so" "pam_rootok.so" "pam_timestamp.so" "pam_tty_audit.so"
    "pam_usertype.so" "pam_sss.so" "pam_ldap.so" "pam_krb5.so"
    "pam_winbind.so" "pam_gnome_keyring.so" "pam_kwallet5.so"
    "pam_fprintd.so" "pam_google_authenticator.so" "pam_u2f.so"
    "pam_yubico.so" "pam_ecryptfs.so" "pam_gdm.so" "pam_apparmor.so"
    "pam_passwdqc.so" "pam_pwhistory.so" "pam_tmpdir.so"
)

# Files where nullok is EXPECTED on many distributions
# (used during system setup, typically for initial login or PAM session management)
NULLOK_EXPECTED_FILES=("common-auth" "system-auth" "login" "su" "su-l")

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
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log()      { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"; }
warn()     { echo -e "${YELLOW}[WARNING]${NC} $1"; ((WARNINGS++)); ((ISSUES_FOUND++)); }
critical() { echo -e "${RED}[CRITICAL]${NC} $1"; ((CRITICAL_ISSUES++)); ((ISSUES_FOUND++)); }
note()     { [[ "$QUIET" == "false" ]] && echo -e "${CYAN}[NOTE]${NC} $1"; ((NOTES++)); }
ok()       { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[OK]${NC} $1"; }
debug()    { [[ "$VERBOSE" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[WARN]${NC} Running without root - some checks may be incomplete"
    fi
}

is_known_module() {
    local module="$1"
    for known in "${KNOWN_MODULES[@]}"; do
        [[ "$module" == "$known" ]] && return 0
    done
    return 1
}

is_nullok_expected() {
    local filename="$1"
    local basename
    basename=$(basename "$filename")
    for expected in "${NULLOK_EXPECTED_FILES[@]}"; do
        [[ "$basename" == "$expected" ]] && return 0
    done
    return 1
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        case "$ID" in
            ubuntu|debian|mint|pop|kali) OS_FAMILY="debian" ;;
            fedora|rhel|centos|rocky|alma|ol|oracle) OS_FAMILY="rhel" ;;
            *) OS_FAMILY="unknown" ;;
        esac
    else
        OS_FAMILY="unknown"
        OS_ID="unknown"
    fi
}

backup_pam_configs() {
    log "Backing up PAM configuration to $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/pam.d "$BACKUP_DIR/"
    cp -a /etc/pam.conf "$BACKUP_DIR/" 2>/dev/null || true
    mkdir -p "$BACKUP_DIR/modules"
    find /lib /lib64 /usr/lib /usr/lib64 -name "pam_*.so" -exec cp {} "$BACKUP_DIR/modules/" \; 2>/dev/null
    chmod -R 600 "$BACKUP_DIR"
    log "Backup complete: $BACKUP_DIR"
}

# --- Parse Arguments ---
# Check for action first
case "${1:-}" in
    audit|restore)
        ACTION="$1"
        shift
        ;;
    -*)
        # Not an action, will be parsed as option below
        ;;
    "")
        # Default to audit
        ;;
    *)
        echo "Unknown action: $1 (use 'audit' or 'restore')"
        usage
        ;;
esac

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -f|--fix) FIX_MODE=true; shift ;;
        -q|--quiet) QUIET=true; shift ;;
        -n|--dry-run) DRY_RUN=true; shift ;;
        -b|--backup) BACKUP=true; shift ;;
        --audit-only) ACTION="audit"; QUIET=true; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# --- Detect OS ---
detect_os

if [[ "$OS_FAMILY" == "debian" ]]; then
    AUTH_FILE="$PAM_DIR/common-auth"
    PASSWORD_FILE="$PAM_DIR/common-password"
else
    AUTH_FILE="$PAM_DIR/system-auth"
    PASSWORD_FILE="$PAM_DIR/system-auth"
fi

# ==============================================================================
# AUDIT MODE
# ==============================================================================
run_audit() {
    check_root

    echo "========================================"
    echo "PAM SECURITY AUDIT"
    echo "Time: $(date)"
    echo "OS: $OS_ID ($OS_FAMILY)"
    echo "========================================"
    echo ""

    # --- CHECK 1: nullok ---
    echo -e "${BOLD}[CHECK 1] NULL Password Handling (nullok)${NC}"

    NULLOK_FILES=$(grep -l "nullok" "$PAM_DIR"/* 2>/dev/null || true)
    if [[ -n "$NULLOK_FILES" ]]; then
        for file in $NULLOK_FILES; do
            if is_nullok_expected "$file"; then
                note "nullok in $file (common default, review if hardening is needed)"
                debug "  This is a standard distribution default"
            else
                warn "nullok in $file (non-standard location - investigate)"
            fi
            if [[ "$VERBOSE" == "true" ]]; then
                grep "nullok" "$file" | while read -r line; do
                    echo "    $line"
                done
            fi
        done

        if [[ "$FIX_MODE" == "true" ]]; then
            for file in $NULLOK_FILES; do
                if [[ "$DRY_RUN" == "true" ]]; then
                    echo -e "  ${BLUE}[DRY-RUN]${NC} Would remove nullok from $file"
                else
                    cp "$file" "${file}.bak.$(date +%s)"
                    sed -i 's/ nullok//g' "$file"
                    log "Removed nullok from $file (backup created)"
                fi
            done
        fi
    else
        ok "No nullok found"
    fi
    echo ""

    # --- CHECK 2: pam_permit.so Backdoors ---
    echo -e "${BOLD}[CHECK 2] pam_permit.so Backdoors${NC}"

    PERMIT_BACKDOORS=false
    for pam_file in "$PAM_DIR"/*; do
        [[ ! -f "$pam_file" ]] && continue

        # pam_permit as sufficient in auth/password = ACTUAL backdoor
        if grep -qE "^(auth|password).*sufficient.*pam_permit\.so" "$pam_file" 2>/dev/null; then
            critical "pam_permit.so BACKDOOR in $pam_file (sufficient auth = anyone can authenticate)"
            grep -n "pam_permit" "$pam_file" | head -3
            PERMIT_BACKDOORS=true
        fi

        # pam_permit as the ONLY auth method
        if grep -qE "^auth.*required.*pam_permit\.so" "$pam_file" 2>/dev/null; then
            if ! grep -qE "^auth.*(pam_unix|pam_sss|pam_ldap|pam_krb5)" "$pam_file" 2>/dev/null; then
                critical "pam_permit.so is ONLY auth method in $pam_file - BACKDOOR"
                PERMIT_BACKDOORS=true
            fi
        fi
    done

    [[ "$PERMIT_BACKDOORS" == "false" ]] && ok "No pam_permit.so backdoors detected"
    echo ""

    # --- CHECK 3: Password Hashing ---
    echo -e "${BOLD}[CHECK 3] Password Hashing Strength${NC}"

    if [[ -f "$PASSWORD_FILE" ]]; then
        if grep -qE "pam_unix\.so.*md5" "$PASSWORD_FILE" 2>/dev/null; then
            critical "MD5 password hashing detected - easily crackable"
            if [[ "$FIX_MODE" == "true" ]]; then
                if [[ "$DRY_RUN" == "true" ]]; then
                    echo -e "  ${BLUE}[DRY-RUN]${NC} Would change md5 to sha512"
                else
                    cp "$PASSWORD_FILE" "${PASSWORD_FILE}.bak.$(date +%s)"
                    sed -i 's/md5/sha512/g' "$PASSWORD_FILE"
                    log "Changed md5 to sha512"
                fi
            fi
        elif grep -qE "pam_unix\.so.*sha512" "$PASSWORD_FILE" 2>/dev/null; then
            ok "SHA512 password hashing in use"
        elif grep -qE "pam_unix\.so.*sha256" "$PASSWORD_FILE" 2>/dev/null; then
            note "SHA256 hashing (SHA512 preferred but SHA256 is adequate)"
        elif grep -qE "pam_unix\.so.*yescrypt" "$PASSWORD_FILE" 2>/dev/null; then
            ok "yescrypt password hashing in use (strong)"
        else
            note "Cannot determine hashing algorithm (check: grep pam_unix $PASSWORD_FILE)"
        fi
    fi
    echo ""

    # --- CHECK 4: Password Quality ---
    echo -e "${BOLD}[CHECK 4] Password Quality Enforcement${NC}"

    if [[ -f "$PASSWORD_FILE" ]]; then
        if grep -qE "pam_pwquality\.so|pam_cracklib\.so" "$PASSWORD_FILE" 2>/dev/null; then
            ok "Password quality module enabled"
            if [[ -f "$PAM_SECURITY_DIR/pwquality.conf" ]]; then
                minlen=$(grep -E "^minlen" "$PAM_SECURITY_DIR/pwquality.conf" 2>/dev/null | cut -d= -f2 | tr -d ' ')
                [[ -n "$minlen" && "$minlen" -lt 12 ]] && note "Min password length is $minlen (consider 12+)"
            fi
        else
            warn "No password quality enforcement found"
        fi
    fi
    echo ""

    # --- CHECK 5: Account Lockout ---
    echo -e "${BOLD}[CHECK 5] Account Lockout Protection${NC}"

    LOCKOUT_FOUND=false
    for check_file in "$AUTH_FILE" "$PAM_DIR/login" "$PAM_DIR/sshd"; do
        if [[ -f "$check_file" ]] && grep -qE "pam_faillock\.so|pam_tally2\.so" "$check_file" 2>/dev/null; then
            LOCKOUT_FOUND=true
            break
        fi
    done

    if [[ "$LOCKOUT_FOUND" == "true" ]]; then
        ok "Account lockout protection enabled"
    else
        warn "No account lockout protection (vulnerable to brute-force)"
    fi
    echo ""

    # --- CHECK 6: Sudo/SSH Backdoors ---
    echo -e "${BOLD}[CHECK 6] Sudo & SSH PAM Backdoors${NC}"

    for svc_file in "$PAM_DIR/sudo" "$PAM_DIR/sshd"; do
        if [[ -f "$svc_file" ]]; then
            svc_name=$(basename "$svc_file")
            if grep -qE "sufficient.*pam_permit\.so" "$svc_file" 2>/dev/null; then
                critical "$svc_name: pam_permit.so allows passwordless access - BACKDOOR"
                grep -n "pam_permit" "$svc_file"
            else
                ok "No backdoor in $svc_name config"
            fi
            if grep -qE "pam_exec\.so" "$svc_file" 2>/dev/null; then
                warn "$svc_name: pam_exec.so found - verify the executed command"
                grep "pam_exec" "$svc_file"
            fi
        fi
    done
    echo ""

    # --- CHECK 7: Unknown Modules ---
    echo -e "${BOLD}[CHECK 7] Unknown PAM Modules${NC}"

    UNKNOWN_MODULES=()
    for pam_file in "$PAM_DIR"/*; do
        [[ ! -f "$pam_file" ]] && continue
        while read -r module; do
            if ! is_known_module "$module" && [[ ! " ${UNKNOWN_MODULES[*]:-} " =~ " $module " ]]; then
                UNKNOWN_MODULES+=("$module")
            fi
        done < <(grep -oP 'pam_\w+\.so' "$pam_file" 2>/dev/null | sort -u)
    done

    if [[ ${#UNKNOWN_MODULES[@]} -gt 0 ]]; then
        note "Unrecognized PAM modules (verify these are legitimate):"
        for module in "${UNKNOWN_MODULES[@]}"; do
            echo "  - $module"
        done
    else
        ok "All PAM modules recognized"
    fi
    echo ""

    # --- CHECK 8: Module Integrity ---
    echo -e "${BOLD}[CHECK 8] PAM Module File Integrity${NC}"

    for dir in /lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security /usr/lib/x86_64-linux-gnu/security; do
        if [[ -d "$dir" ]]; then
            recent=$(find "$dir" -name "pam_*.so" -mtime -1 2>/dev/null)
            [[ -n "$recent" ]] && warn "Recently modified PAM modules (last 24h): $recent"

            writable=$(find "$dir" -name "pam_*.so" -perm -002 2>/dev/null)
            [[ -n "$writable" ]] && critical "World-writable PAM modules: $writable"
            break
        fi
    done
    ok "Module integrity check complete"
    echo ""

    # --- CHECK 9: Shadow File ---
    echo -e "${BOLD}[CHECK 9] Shadow File Password Analysis${NC}"

    if [[ -r /etc/shadow ]]; then
        empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || length($2) < 3) && $2 !~ /^[!*]/ {print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_pass" ]]; then
            critical "Accounts with empty/no passwords: $empty_pass"
        else
            ok "No accounts with empty passwords"
        fi

        md5_users=$(awk -F: '$2 ~ /^\$1\$/ {print $1}' /etc/shadow 2>/dev/null)
        [[ -n "$md5_users" ]] && warn "Accounts using weak MD5 hashes: $md5_users"
    else
        note "Cannot read /etc/shadow (run as root)"
    fi
    echo ""

    # --- Summary ---
    echo "========================================"
    echo "AUDIT SUMMARY"
    echo "========================================"
    echo ""
    echo -e "Critical issues:  ${RED}$CRITICAL_ISSUES${NC}"
    echo -e "Warnings:         ${YELLOW}$WARNINGS${NC}"
    echo -e "Notes:            ${CYAN}$NOTES${NC}"
    echo ""

    if [[ $CRITICAL_ISSUES -gt 0 ]]; then
        echo -e "${RED}CRITICAL ISSUES DETECTED - Investigate immediately${NC}"
        echo ""
        echo "To attempt automatic fixes: $0 audit --fix"
        echo "To restore PAM from packages: $0 restore"
        return 1
    elif [[ $WARNINGS -gt 0 ]]; then
        echo -e "${YELLOW}Warnings found - review recommended${NC}"
    else
        echo -e "${GREEN}No critical PAM issues detected${NC}"
    fi
    return 0
}

# ==============================================================================
# RESTORE MODE
# ==============================================================================
run_restore() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} Restore must be run as root"
        exit 2
    fi

    echo "========================================"
    echo "PAM EMERGENCY RESTORE - $(hostname)"
    echo "Time: $(date)"
    echo "OS: $OS_ID ($OS_FAMILY)"
    echo "========================================"

    if [[ "$OS_FAMILY" == "unknown" ]]; then
        echo -e "${RED}[ERROR]${NC} Unsupported OS: $OS_ID"
        exit 2
    fi

    echo ""
    echo -e "${RED}WARNING: This resets ALL PAM configuration to defaults!${NC}"
    echo ""

    if [[ "$DRY_RUN" == "false" && "$FIX_MODE" == "false" ]]; then
        read -rp "Type 'RESTORE PAM' to confirm: " confirm
        if [[ "$confirm" != "RESTORE PAM" ]]; then
            echo "Aborted."
            exit 2
        fi
    fi

    [[ "$BACKUP" == "true" && "$DRY_RUN" == "false" ]] && backup_pam_configs

    if [[ "$OS_FAMILY" == "debian" ]]; then
        local pam_packages
        pam_packages=$(dpkg -S /etc/pam.d/* 2>/dev/null | cut -d: -f1 | sort -u | tr '\n' ' ')
        pam_packages="${pam_packages:-libpam-modules libpam-runtime login passwd}"

        if [[ "$DRY_RUN" == "true" ]]; then
            echo -e "${BLUE}[DRY-RUN]${NC} Would reinstall: $pam_packages"
        else
            log "Reinstalling PAM packages..."
            DEBIAN_FRONTEND=noninteractive apt-get install --reinstall \
                -o Dpkg::Options::="--force-confnew" \
                -o Dpkg::Options::="--force-confmiss" \
                -y $pam_packages

            DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
                libpam-modules libpam-modules-bin libpam-runtime libpam0g
        fi
    else
        local pam_packages
        pam_packages=$(rpm -qf /etc/pam.d/* 2>/dev/null | sort -u | grep -v "not owned" | tr '\n' ' ')
        pam_packages="${pam_packages:-pam}"

        if [[ "$DRY_RUN" == "true" ]]; then
            echo -e "${BLUE}[DRY-RUN]${NC} Would reinstall: $pam_packages"
        else
            log "Reinstalling PAM packages..."
            if command -v dnf &>/dev/null; then
                dnf reinstall -y $pam_packages pam 2>/dev/null || true
            else
                yum reinstall -y $pam_packages pam 2>/dev/null || true
            fi
        fi
    fi

    # Verify
    if [[ "$DRY_RUN" == "false" ]]; then
        echo ""
        log "Verifying PAM installation..."
        local errors=0

        for mod in pam_unix.so pam_deny.so pam_permit.so; do
            local mod_path
            mod_path=$(find /lib /lib64 /usr/lib /usr/lib64 -name "$mod" 2>/dev/null | head -1)
            if [[ -z "$mod_path" ]]; then
                echo -e "${RED}[ERROR]${NC} Missing: $mod"; ((errors++))
            elif ! file "$mod_path" | grep -q "ELF"; then
                echo -e "${RED}[ERROR]${NC} Invalid binary: $mod_path"; ((errors++))
            else
                log "Verified: $mod"
            fi
        done

        if [[ $errors -gt 0 ]]; then
            echo -e "${RED}PAM verification found $errors errors${NC}"
        else
            log "PAM verification passed"
        fi

        echo ""
        echo -e "${YELLOW}IMPORTANT: Test authentication before logging out!${NC}"
        echo -e "${YELLOW}Open a new SSH session to verify login still works.${NC}"
    fi

    [[ "$BACKUP" == "true" ]] && echo "Backup: $BACKUP_DIR"
}

# ==============================================================================
# MAIN
# ==============================================================================
case "$ACTION" in
    audit)   run_audit ;;
    restore) run_restore ;;
esac
