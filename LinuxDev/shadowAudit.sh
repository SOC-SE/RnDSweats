#!/bin/bash
# ==============================================================================
# Script Name: shadowAudit.sh
# Description: Audit /etc/shadow for security issues including weak hashes,
#              password age, account status, and suspicious modifications
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./shadowAudit.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -v, --verbose    Show all accounts (not just issues)
#   -q, --quiet      Only show critical issues
#   -f, --fix        Lock accounts with issues (interactive)
#   -j, --json       Output in JSON format
#
# What Gets Checked:
#   - Empty/blank passwords
#   - Weak hash algorithms (DES, MD5)
#   - Accounts that never expire
#   - Recently changed passwords (possible compromise)
#   - Accounts with no password aging
#   - Shadow file permissions and ownership
#   - Shadow file modification time
#
# Hash Types:
#   $1$ = MD5 (weak - crackable in seconds)
#   $2a$/$2b$ = Blowfish (acceptable)
#   $5$ = SHA-256 (good)
#   $6$ = SHA-512 (best - recommended)
#   $y$ = yescrypt (modern, very strong)
#
# Exit Codes:
#   0 - No critical issues
#   1 - Critical issues found
#   2 - Error (permission denied, etc.)
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
VERBOSE=false
QUIET=false
FIX_MODE=false
JSON_OUTPUT=false

# Counters
TOTAL_ACCOUNTS=0
CRITICAL_ISSUES=0
WARNINGS=0
EMPTY_PASSWORDS=0
WEAK_HASHES=0
NEVER_EXPIRES=0
RECENT_CHANGES=0

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

log() {
    [[ "$QUIET" == "false" && "$JSON_OUTPUT" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    [[ "$JSON_OUTPUT" == "false" ]] && echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

critical() {
    [[ "$JSON_OUTPUT" == "false" ]] && echo -e "${RED}[CRITICAL]${NC} $1"
    ((CRITICAL_ISSUES++))
}

ok() {
    [[ "$QUIET" == "false" && "$JSON_OUTPUT" == "false" ]] && echo -e "${GREEN}[OK]${NC} $1"
}

debug() {
    [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" ]] && echo -e "${BLUE}[DEBUG]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        if [[ "$JSON_OUTPUT" == "false" ]]; then
            echo -e "${RED}[ERROR]${NC} This script must be run as root to read /etc/shadow"
        fi
        exit 2
    fi
}

# Determine hash type from password field
get_hash_type() {
    local hash="$1"

    case "$hash" in
        \$1\$*)
            echo "MD5"
            ;;
        \$2a\$*|\$2b\$*|\$2y\$*)
            echo "Blowfish"
            ;;
        \$5\$*)
            echo "SHA-256"
            ;;
        \$6\$*)
            echo "SHA-512"
            ;;
        \$y\$*)
            echo "yescrypt"
            ;;
        "!"|"!!"|"!")
            echo "Locked"
            ;;
        "*"|"*LK*")
            echo "Disabled"
            ;;
        "")
            echo "Empty"
            ;;
        *)
            # DES or unknown
            if [[ ${#hash} -eq 13 ]]; then
                echo "DES"
            else
                echo "Unknown"
            fi
            ;;
    esac
}

# Convert days since epoch to date
days_to_date() {
    local days="$1"
    if [[ -n "$days" && "$days" =~ ^[0-9]+$ && "$days" -gt 0 ]]; then
        date -d "1970-01-01 + $days days" "+%Y-%m-%d" 2>/dev/null || echo "Unknown"
    else
        echo "Never"
    fi
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
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -f|--fix)
            FIX_MODE=true
            shift
            ;;
        -j|--json)
            JSON_OUTPUT=true
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

if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo "========================================"
    echo "/etc/shadow SECURITY AUDIT"
    echo "Time: $(date)"
    echo "========================================"
    echo ""
fi

# ==============================================================================
# CHECK: Shadow File Permissions
# ==============================================================================
if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo -e "${BOLD}[CHECK] Shadow File Permissions${NC}"
fi

SHADOW_PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null)
SHADOW_OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null)
SHADOW_MTIME=$(stat -c "%y" /etc/shadow 2>/dev/null | cut -d. -f1)

if [[ "$SHADOW_PERMS" != "000" && "$SHADOW_PERMS" != "600" && "$SHADOW_PERMS" != "640" ]]; then
    critical "Shadow file has insecure permissions: $SHADOW_PERMS (should be 600 or 640)"
    if [[ "$FIX_MODE" == "true" ]]; then
        chmod 640 /etc/shadow
        log "Fixed permissions to 640"
    fi
else
    ok "Shadow file permissions: $SHADOW_PERMS"
fi

if [[ "$SHADOW_OWNER" != "root:root" && "$SHADOW_OWNER" != "root:shadow" ]]; then
    critical "Shadow file has wrong ownership: $SHADOW_OWNER"
    if [[ "$FIX_MODE" == "true" ]]; then
        chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow
        log "Fixed ownership"
    fi
else
    ok "Shadow file ownership: $SHADOW_OWNER"
fi

log "Shadow file last modified: $SHADOW_MTIME"

# Check if modified in last 24 hours
SHADOW_MTIME_EPOCH=$(stat -c "%Y" /etc/shadow 2>/dev/null)
NOW_EPOCH=$(date +%s)
DIFF_HOURS=$(( (NOW_EPOCH - SHADOW_MTIME_EPOCH) / 3600 ))
if [[ $DIFF_HOURS -lt 24 ]]; then
    warn "Shadow file modified within last 24 hours - verify changes are authorized"
fi

if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo ""
fi

# ==============================================================================
# CHECK: Account Analysis
# ==============================================================================
if [[ "$JSON_OUTPUT" == "false" ]]; then
    echo -e "${BOLD}[CHECK] Account Analysis${NC}"
    echo ""
    printf "%-20s %-12s %-12s %-12s %s\n" "USERNAME" "HASH_TYPE" "LAST_CHANGE" "EXPIRES" "STATUS"
    echo "--------------------------------------------------------------------------------"
fi

# JSON array for output
JSON_ACCOUNTS="["

# Store accounts with issues for fix mode
ACCOUNTS_WITH_ISSUES=()

while IFS=: read -r username password last_change min_days max_days warn_days inactive_days expire_date reserved; do
    ((TOTAL_ACCOUNTS++))

    hash_type=$(get_hash_type "$password")
    last_change_date=$(days_to_date "$last_change")
    expire_date_fmt=$(days_to_date "$expire_date")

    # Determine status
    status="OK"
    issues=""

    # Check for empty password
    if [[ "$hash_type" == "Empty" ]]; then
        status="CRITICAL"
        issues="Empty password"
        ((EMPTY_PASSWORDS++))
        ((CRITICAL_ISSUES++))
        ACCOUNTS_WITH_ISSUES+=("$username:empty")
    fi

    # Check for weak hash
    if [[ "$hash_type" == "MD5" || "$hash_type" == "DES" ]]; then
        if [[ "$status" == "OK" ]]; then
            status="WARNING"
        fi
        issues="${issues}${issues:+, }Weak hash ($hash_type)"
        ((WEAK_HASHES++))
        ((WARNINGS++))
        ACCOUNTS_WITH_ISSUES+=("$username:weak_hash")
    fi

    # Check for never-expiring password (only for non-system accounts)
    if [[ "$hash_type" != "Locked" && "$hash_type" != "Disabled" && "$hash_type" != "Empty" ]]; then
        if [[ -z "$max_days" || "$max_days" == "99999" || "$max_days" == "-1" ]]; then
            # Only warn for real users (UID >= 1000) or root
            uid=$(id -u "$username" 2>/dev/null || echo "0")
            if [[ "$uid" -ge 1000 || "$username" == "root" ]]; then
                if [[ "$status" == "OK" ]]; then
                    status="INFO"
                fi
                issues="${issues}${issues:+, }Never expires"
                ((NEVER_EXPIRES++))
            fi
        fi
    fi

    # Check for recently changed password (last 24 hours)
    if [[ -n "$last_change" && "$last_change" =~ ^[0-9]+$ && "$last_change" -gt 0 ]]; then
        today_days=$(( $(date +%s) / 86400 ))
        if [[ $((today_days - last_change)) -lt 1 ]]; then
            if [[ "$status" == "OK" ]]; then
                status="INFO"
            fi
            issues="${issues}${issues:+, }Changed today"
            ((RECENT_CHANGES++))
        fi
    fi

    # Output based on verbosity
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        JSON_ACCOUNTS+="{\"username\":\"$username\",\"hash_type\":\"$hash_type\",\"last_change\":\"$last_change_date\",\"expires\":\"$expire_date_fmt\",\"status\":\"$status\",\"issues\":\"$issues\"},"
    elif [[ "$VERBOSE" == "true" || "$status" != "OK" ]]; then
        case "$status" in
            "CRITICAL")
                printf "${RED}%-20s %-12s %-12s %-12s %s${NC}\n" "$username" "$hash_type" "$last_change_date" "$expire_date_fmt" "$issues"
                ;;
            "WARNING")
                printf "${YELLOW}%-20s %-12s %-12s %-12s %s${NC}\n" "$username" "$hash_type" "$last_change_date" "$expire_date_fmt" "$issues"
                ;;
            "INFO")
                printf "${CYAN}%-20s %-12s %-12s %-12s %s${NC}\n" "$username" "$hash_type" "$last_change_date" "$expire_date_fmt" "$issues"
                ;;
            *)
                [[ "$VERBOSE" == "true" ]] && printf "%-20s %-12s %-12s %-12s %s\n" "$username" "$hash_type" "$last_change_date" "$expire_date_fmt" "-"
                ;;
        esac
    fi

done < /etc/shadow

# Close JSON array
JSON_ACCOUNTS="${JSON_ACCOUNTS%,}]"

if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$JSON_ACCOUNTS" | python3 -m json.tool 2>/dev/null || echo "$JSON_ACCOUNTS"
    exit 0
fi

echo ""

# ==============================================================================
# CHECK: UID 0 Accounts
# ==============================================================================
echo -e "${BOLD}[CHECK] Root-Level Accounts (UID 0)${NC}"

UID0_ACCOUNTS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
UID0_COUNT=$(echo "$UID0_ACCOUNTS" | grep -c . || echo "0")

if [[ "$UID0_COUNT" -gt 1 ]]; then
    critical "Multiple accounts with UID 0 detected!"
    echo "$UID0_ACCOUNTS" | while read -r acc; do
        echo "  - $acc"
    done
    echo "  Only 'root' should have UID 0"
else
    ok "Only root has UID 0"
fi
echo ""

# ==============================================================================
# CHECK: Login-Capable Accounts
# ==============================================================================
echo -e "${BOLD}[CHECK] Login-Capable Accounts${NC}"

LOGIN_CAPABLE=$(grep -vE '/nologin$|/false$|/sync$|/shutdown$|/halt$' /etc/passwd | cut -d: -f1)
LOGIN_COUNT=$(echo "$LOGIN_CAPABLE" | wc -l)

log "$LOGIN_COUNT accounts have login capability"

if [[ "$VERBOSE" == "true" ]]; then
    echo "Login-capable accounts:"
    echo "$LOGIN_CAPABLE" | while read -r acc; do
        echo "  - $acc"
    done
fi
echo ""

# ==============================================================================
# FIX MODE
# ==============================================================================
if [[ "$FIX_MODE" == "true" && ${#ACCOUNTS_WITH_ISSUES[@]} -gt 0 ]]; then
    echo "========================================"
    echo "FIX MODE"
    echo "========================================"
    echo ""

    for entry in "${ACCOUNTS_WITH_ISSUES[@]}"; do
        username="${entry%%:*}"
        issue="${entry##*:}"

        echo -e "Account: ${YELLOW}$username${NC} (Issue: $issue)"
        read -rp "Lock this account? [y/N]: " confirm
        confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')

        if [[ "$confirm" == "y" || "$confirm" == "yes" ]]; then
            passwd -l "$username" 2>/dev/null && log "Locked account: $username" || warn "Failed to lock: $username"
        else
            log "Skipped: $username"
        fi
        echo ""
    done
fi

# ==============================================================================
# SUMMARY
# ==============================================================================
echo "========================================"
echo "AUDIT SUMMARY"
echo "========================================"
echo ""
echo "Total accounts analyzed:   $TOTAL_ACCOUNTS"
echo -e "Empty passwords:           ${RED}$EMPTY_PASSWORDS${NC}"
echo -e "Weak hashes (MD5/DES):     ${YELLOW}$WEAK_HASHES${NC}"
echo "Never-expiring passwords:  $NEVER_EXPIRES"
echo "Recently changed:          $RECENT_CHANGES"
echo ""
echo -e "Critical issues:           ${RED}$CRITICAL_ISSUES${NC}"
echo -e "Warnings:                  ${YELLOW}$WARNINGS${NC}"
echo ""

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    echo -e "${RED}CRITICAL ISSUES DETECTED!${NC}"
    echo ""
    echo "Recommended actions:"
    echo "  1. Lock accounts with empty passwords: passwd -l <username>"
    echo "  2. Force password reset for weak hashes: chage -d 0 <username>"
    echo "  3. Set password expiration: chage -M 90 <username>"
    echo ""
    echo "Run with --fix to interactively lock problematic accounts"
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}Warnings found - review recommended${NC}"
    exit 0
else
    echo -e "${GREEN}No critical shadow issues detected${NC}"
    exit 0
fi
