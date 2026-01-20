#!/bin/bash
# ==============================================================================
# Log Analysis - Linux
# Quick security log review for incident response
# ==============================================================================

echo "========================================"
echo "LOG ANALYSIS - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/10] FAILED SSH LOGINS (Last 50)"
echo "----------------------------------------"
grep -i "failed\|failure" /var/log/auth.log 2>/dev/null | tail -50 || \
grep -i "failed\|failure" /var/log/secure 2>/dev/null | tail -50 || \
journalctl -u sshd | grep -i "failed\|failure" | tail -50

echo -e "\n[2/10] SUCCESSFUL LOGINS"
echo "----------------------------------------"
last -n 20 2>/dev/null || lastlog | head -20

echo -e "\n[3/10] FAILED LOGIN SOURCES (By IP)"
echo "----------------------------------------"
grep -i "failed" /var/log/auth.log 2>/dev/null | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn | head -10 || \
grep -i "failed" /var/log/secure 2>/dev/null | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn | head -10

echo -e "\n[4/10] SUDO COMMANDS"
echo "----------------------------------------"
grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -30 || \
grep -i "sudo" /var/log/secure 2>/dev/null | tail -30

echo -e "\n[5/10] USER ACCOUNT CHANGES"
echo "----------------------------------------"
grep -iE "useradd|userdel|usermod|passwd|groupadd" /var/log/auth.log 2>/dev/null | tail -20 || \
grep -iE "useradd|userdel|usermod|passwd|groupadd" /var/log/secure 2>/dev/null | tail -20

echo -e "\n[6/10] SERVICE START/STOP"
echo "----------------------------------------"
journalctl --since "24 hours ago" | grep -iE "started|stopped|failed" | tail -30

echo -e "\n[7/10] CRON EXECUTION"
echo "----------------------------------------"
grep -i cron /var/log/syslog 2>/dev/null | tail -20 || \
grep -i cron /var/log/cron 2>/dev/null | tail -20 || \
journalctl -u cron | tail -20

echo -e "\n[8/10] KERNEL MESSAGES (Errors)"
echo "----------------------------------------"
dmesg | grep -iE "error|fail|warn" | tail -20

echo -e "\n[9/10] PACKAGE INSTALLATION"
echo "----------------------------------------"
grep -i "install" /var/log/dpkg.log 2>/dev/null | tail -10 || \
grep -i "install" /var/log/yum.log 2>/dev/null | tail -10 || \
grep -i "install" /var/log/dnf.log 2>/dev/null | tail -10

echo -e "\n[10/10] SUSPICIOUS LOG ENTRIES"
echo "----------------------------------------"
grep -iE "(reverse shell|nc -e|bash -i|/dev/tcp|curl.*\|.*sh|wget.*\|.*sh|base64.*decode)" /var/log/*.log 2>/dev/null | head -20 || echo "None found"

echo -e "\n========================================"
echo "LOG ANALYSIS COMPLETE"
echo "========================================"
