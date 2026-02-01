#!/bin/bash
# ==============================================================================
# User Audit - Linux
# Comprehensive user account security check
# For Salt-GUI / CCDC Competition Use
#
# New script for Salt-GUI (no Windows equivalent existed for Linux)
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "USER AUDIT - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/12] ALL LOCAL USERS"
echo "----------------------------------------"
awk -F: '{printf "%-20s UID: %-6s GID: %-6s Home: %-25s Shell: %s\n", $1, $3, $4, $6, $7}' /etc/passwd

echo -e "\n[2/12] HUMAN USERS (UID >= 1000)"
echo "----------------------------------------"
awk -F: '($3 >= 1000 && $1 != "nobody") || $1 == "root" {printf "%-20s UID: %-6s Shell: %s\n", $1, $3, $7}' /etc/passwd

echo -e "\n[3/12] USERS WITH LOGIN SHELLS"
echo "----------------------------------------"
grep -vE "(/sbin/nologin|/bin/false|/usr/sbin/nologin)" /etc/passwd | awk -F: '{printf "%-20s Shell: %s\n", $1, $7}'

echo -e "\n[4/12] ADMINISTRATORS (sudo/wheel group)"
echo "----------------------------------------"
echo "=== sudo group ==="
getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' || echo "sudo group not found"
echo ""
echo "=== wheel group ==="
getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' || echo "wheel group not found"

echo -e "\n[5/12] USERS WITH UID 0 (Root Equivalents)"
echo "----------------------------------------"
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo -e "\n[6/12] USERS WITH EMPTY PASSWORDS"
echo "----------------------------------------"
if [ -r /etc/shadow ]; then
    awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1 " - " $2}' /etc/shadow 2>/dev/null || echo "Permission denied"
else
    echo "Cannot read /etc/shadow - run as root"
fi

echo -e "\n[7/12] PASSWORD AGING INFO"
echo "----------------------------------------"
if [ -r /etc/shadow ]; then
    echo "User               Last Changed    Min  Max  Warn  Inactive  Expire"
    echo "----------------   ------------    ---  ---  ----  --------  ------"
    while IFS=: read -r user pass lastchg min max warn inactive expire _; do
        if [ -n "$lastchg" ] && [ "$lastchg" != "" ]; then
            printf "%-18s %-15s %-4s %-4s %-5s %-9s %s\n" "$user" "$lastchg" "$min" "$max" "$warn" "$inactive" "$expire"
        fi
    done < /etc/shadow | head -20
else
    echo "Cannot read /etc/shadow - run as root"
fi

echo -e "\n[8/12] RECENT LOGIN HISTORY"
echo "----------------------------------------"
last -n 20 2>/dev/null || echo "last command not available"

echo -e "\n[9/12] FAILED LOGIN ATTEMPTS"
echo "----------------------------------------"
if [ -f /var/log/auth.log ]; then
    grep -i "failed" /var/log/auth.log 2>/dev/null | tail -20 || echo "None found"
elif [ -f /var/log/secure ]; then
    grep -i "failed" /var/log/secure 2>/dev/null | tail -20 || echo "None found"
else
    echo "Auth log not found"
fi

echo -e "\n[10/12] CURRENTLY LOGGED IN USERS"
echo "----------------------------------------"
who 2>/dev/null || echo "who command not available"

echo -e "\n[11/12] SUDOERS FILE CHECK"
echo "----------------------------------------"
if [ -r /etc/sudoers ]; then
    echo "=== /etc/sudoers (non-comments) ==="
    grep -vE "^#|^$|^Defaults" /etc/sudoers 2>/dev/null | head -20
    echo ""
    echo "=== /etc/sudoers.d/ files ==="
    ls -la /etc/sudoers.d/ 2>/dev/null || echo "No sudoers.d directory"
else
    echo "Cannot read /etc/sudoers - run as root"
fi

echo -e "\n[12/12] ALL LOCAL GROUPS"
echo "----------------------------------------"
cut -d: -f1 /etc/group | sort | head -40

echo -e "\n========================================"
echo "USER AUDIT COMPLETE"
echo "========================================"
