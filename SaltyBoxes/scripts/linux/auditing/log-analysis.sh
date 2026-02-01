#!/bin/bash
# ==============================================================================
# Log Analysis - Linux
# Quick security log review for incident response
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "LOG ANALYSIS - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/10] FAILED SSH LOGINS (Last 50)"
echo "----------------------------------------"
if [ -f /var/log/auth.log ]; then
    grep -i "failed\|failure" /var/log/auth.log 2>/dev/null | tail -50 || echo "No failures found"
elif [ -f /var/log/secure ]; then
    grep -i "failed\|failure" /var/log/secure 2>/dev/null | tail -50 || echo "No failures found"
else
    journalctl -u sshd 2>/dev/null | grep -i "failed\|failure" | tail -50 || echo "No failures found"
fi

echo -e "\n[2/10] SUCCESSFUL LOGINS"
echo "----------------------------------------"
last -n 20 2>/dev/null || lastlog 2>/dev/null | head -20 || echo "Unable to retrieve login history"

echo -e "\n[3/10] FAILED LOGIN SOURCES (By IP)"
echo "----------------------------------------"
if [ -f /var/log/auth.log ]; then
    grep -i "failed" /var/log/auth.log 2>/dev/null | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn | head -10 || echo "None found"
elif [ -f /var/log/secure ]; then
    grep -i "failed" /var/log/secure 2>/dev/null | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn | head -10 || echo "None found"
else
    echo "Auth log not found"
fi

echo -e "\n[4/10] SUDO COMMANDS"
echo "----------------------------------------"
if [ -f /var/log/auth.log ]; then
    grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -30 || echo "None found"
elif [ -f /var/log/secure ]; then
    grep -i "sudo" /var/log/secure 2>/dev/null | tail -30 || echo "None found"
else
    journalctl 2>/dev/null | grep -i "sudo" | tail -30 || echo "None found"
fi

echo -e "\n[5/10] USER ACCOUNT CHANGES"
echo "----------------------------------------"
if [ -f /var/log/auth.log ]; then
    grep -iE "useradd|userdel|usermod|passwd|groupadd" /var/log/auth.log 2>/dev/null | tail -20 || echo "None found"
elif [ -f /var/log/secure ]; then
    grep -iE "useradd|userdel|usermod|passwd|groupadd" /var/log/secure 2>/dev/null | tail -20 || echo "None found"
else
    echo "Auth log not found"
fi

echo -e "\n[6/10] SERVICE START/STOP (Last 24h)"
echo "----------------------------------------"
journalctl --since "24 hours ago" 2>/dev/null | grep -iE "started|stopped|failed" | tail -30 || echo "journalctl not available"

echo -e "\n[7/10] CRON EXECUTION"
echo "----------------------------------------"
if [ -f /var/log/syslog ]; then
    grep -i cron /var/log/syslog 2>/dev/null | tail -20 || echo "None found"
elif [ -f /var/log/cron ]; then
    tail -20 /var/log/cron 2>/dev/null || echo "None found"
else
    journalctl -u cron 2>/dev/null | tail -20 || journalctl -u crond 2>/dev/null | tail -20 || echo "Cron logs not available"
fi

echo -e "\n[8/10] KERNEL MESSAGES (Errors)"
echo "----------------------------------------"
dmesg 2>/dev/null | grep -iE "error|fail|warn" | tail -20 || echo "dmesg not available or permission denied"

echo -e "\n[9/10] PACKAGE INSTALLATION"
echo "----------------------------------------"
if [ -f /var/log/dpkg.log ]; then
    grep -i "install" /var/log/dpkg.log 2>/dev/null | tail -10 || echo "None found"
elif [ -f /var/log/dnf.log ]; then
    grep -i "install" /var/log/dnf.log 2>/dev/null | tail -10 || echo "None found"
elif [ -f /var/log/yum.log ]; then
    grep -i "install" /var/log/yum.log 2>/dev/null | tail -10 || echo "None found"
else
    echo "Package log not found"
fi

echo -e "\n[10/10] SUSPICIOUS LOG ENTRIES"
echo "----------------------------------------"
suspicious_patterns="reverse shell|nc -e|bash -i|/dev/tcp|curl.*\|.*sh|wget.*\|.*sh|base64.*decode|python.*-c.*import|perl.*-e"
found=0
for logfile in /var/log/*.log; do
    if [ -f "$logfile" ]; then
        matches=$(grep -iE "$suspicious_patterns" "$logfile" 2>/dev/null | head -5)
        if [ -n "$matches" ]; then
            echo "=== $logfile ==="
            echo "$matches"
            found=1
        fi
    fi
done
[ $found -eq 0 ] && echo "None found"

echo -e "\n========================================"
echo "LOG ANALYSIS COMPLETE"
echo "========================================"
