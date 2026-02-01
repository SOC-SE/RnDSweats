#!/bin/bash
# ==============================================================================
# Service Audit - Linux
# Comprehensive service security check
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "SERVICE AUDIT - $(hostname)"
echo "Time: $(date)"
echo "========================================"

# Check if systemctl is available
if ! command -v systemctl &>/dev/null; then
    echo "ERROR: systemctl not available. This script requires systemd."
    exit 1
fi

echo -e "\n[1/8] ALL ENABLED SERVICES"
echo "----------------------------------------"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -v "^UNIT" | head -40 || echo "Unable to list services"

echo -e "\n[2/8] CURRENTLY RUNNING SERVICES"
echo "----------------------------------------"
systemctl list-units --type=service --state=running 2>/dev/null | grep -v "^UNIT\|^LOAD\|loaded units" | head -40 || echo "Unable to list running services"

echo -e "\n[3/8] FAILED SERVICES"
echo "----------------------------------------"
failed=$(systemctl list-units --type=service --state=failed 2>/dev/null)
if [ -n "$failed" ]; then
    echo "$failed"
else
    echo "No failed services"
fi

echo -e "\n[4/8] SUSPICIOUS/UNKNOWN SERVICES"
echo "----------------------------------------"
# Services not in common list - potential backdoors
known_services="sshd|NetworkManager|systemd|dbus|rsyslog|cron|crond|salt|firewalld|iptables|auditd|chronyd|ntpd|postfix|httpd|nginx|apache|mysql|mariadb|postgresql|docker|containerd|kubelet"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | \
    grep -vE "($known_services)" | \
    grep enabled | head -20 || echo "None found"

echo -e "\n[5/8] SERVICES LISTENING ON NETWORK"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tulnp 2>/dev/null | while read -r line; do
        proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' 2>/dev/null || true)
        port=$(echo "$line" | awk '{print $5}')
        if [ -n "$proc" ]; then
            echo "$port -> $proc"
        fi
    done | sort -u || echo "Unable to determine"
else
    echo "ss not available"
fi

echo -e "\n[6/8] SERVICES RUNNING AS ROOT"
echo "----------------------------------------"
ps aux 2>/dev/null | grep -E "^root" | grep -vE "(ps|grep|bash|sshd|systemd|salt)" | awk '{print $11}' | sort -u | head -20 || echo "Unable to list"

echo -e "\n[7/8] RECENTLY MODIFIED SERVICE FILES (Last 7 days)"
echo "----------------------------------------"
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -7 2>/dev/null | head -20 || echo "None found"

echo -e "\n[8/8] SOCKET ACTIVATED SERVICES"
echo "----------------------------------------"
systemctl list-sockets --all 2>/dev/null | head -20 || echo "Unable to list sockets"

echo -e "\n========================================"
echo "SERVICE AUDIT COMPLETE"
echo "========================================"
