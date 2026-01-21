#!/bin/bash
# ==============================================================================
# Service Audit - Linux
# Comprehensive service security check
# ==============================================================================

echo "========================================"
echo "SERVICE AUDIT - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/8] ALL ENABLED SERVICES"
echo "----------------------------------------"
systemctl list-unit-files --type=service --state=enabled | grep -v "^UNIT" | head -40

echo -e "\n[2/8] CURRENTLY RUNNING SERVICES"
echo "----------------------------------------"
systemctl list-units --type=service --state=running | grep -v "^UNIT\|^LOAD\|loaded units" | head -40

echo -e "\n[3/8] FAILED SERVICES"
echo "----------------------------------------"
systemctl list-units --type=service --state=failed

echo -e "\n[4/8] SUSPICIOUS/UNKNOWN SERVICES"
echo "----------------------------------------"
# Services not in common list
systemctl list-unit-files --type=service --state=enabled | \
    grep -vE "(sshd|NetworkManager|systemd|dbus|rsyslog|cron|salt|firewalld|iptables|auditd|chronyd|ntpd|postfix|httpd|nginx|apache|mysql|mariadb|postgresql|docker)" | \
    grep enabled | head -20

echo -e "\n[5/8] SERVICES LISTENING ON NETWORK"
echo "----------------------------------------"
ss -tulnp | while read line; do
    proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+')
    port=$(echo "$line" | awk '{print $5}')
    if [ -n "$proc" ]; then
        echo "$port -> $proc"
    fi
done 2>/dev/null | sort -u

echo -e "\n[6/8] SERVICES RUNNING AS ROOT"
echo "----------------------------------------"
ps aux | grep -E "^root" | grep -vE "(ps|grep|bash|sshd|systemd|salt)" | awk '{print $11}' | sort -u | head -20

echo -e "\n[7/8] RECENTLY MODIFIED SERVICE FILES"
echo "----------------------------------------"
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -7 2>/dev/null | head -20

echo -e "\n[8/8] SOCKET ACTIVATED SERVICES"
echo "----------------------------------------"
systemctl list-sockets --all | head -20

echo -e "\n========================================"
echo "SERVICE AUDIT COMPLETE"
echo "========================================"
