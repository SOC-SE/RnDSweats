#!/bin/bash
# ==============================================================================
# Host Isolation Script - Linux
# Immediately isolate a compromised host while maintaining Salt connectivity
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

SALT_MASTER_IP="${1:-}"

echo "========================================"
echo "HOST ISOLATION - $(hostname)"
echo "Time: $(date)"
echo "========================================"

if [ -z "$SALT_MASTER_IP" ]; then
    # Try to detect Salt master from minion config
    SALT_MASTER_IP=$(grep -E "^master:" /etc/salt/minion 2>/dev/null | awk '{print $2}' | head -1)
    if [ -z "$SALT_MASTER_IP" ]; then
        echo "ERROR: Salt master IP required. Usage: $0 <salt_master_ip>"
        exit 1
    fi
    echo "Detected Salt Master: $SALT_MASTER_IP"
fi

echo -e "\n[1/5] FLUSHING EXISTING IPTABLES RULES"
echo "----------------------------------------"
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo -e "\n[2/5] SETTING DEFAULT POLICIES TO DROP"
echo "----------------------------------------"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
echo "Default policies set to DROP"

echo -e "\n[3/5] ALLOWING SALT COMMUNICATION"
echo "----------------------------------------"
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow Salt master communication (ports 4505, 4506)
iptables -A INPUT -p tcp -s "$SALT_MASTER_IP" --dport 4505 -j ACCEPT
iptables -A INPUT -p tcp -s "$SALT_MASTER_IP" --dport 4506 -j ACCEPT
iptables -A OUTPUT -p tcp -d "$SALT_MASTER_IP" --dport 4505 -j ACCEPT
iptables -A OUTPUT -p tcp -d "$SALT_MASTER_IP" --dport 4506 -j ACCEPT

# Allow DNS for Salt (optional, might be needed)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

echo "Salt master ($SALT_MASTER_IP) communication allowed"

echo -e "\n[4/5] KILLING NON-ESSENTIAL NETWORK SERVICES"
echo "----------------------------------------"
# Stop services that could be exploited
for svc in sshd apache2 nginx httpd vsftpd smbd nmbd telnet rsh; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null && echo "Stopped: $svc" || true
    fi
done

echo -e "\n[5/5] KILLING ACTIVE USER SESSIONS"
echo "----------------------------------------"
# Kill all SSH sessions except salt processes
pkill -9 -f "sshd.*@" 2>/dev/null || echo "No SSH sessions to kill"

# List what's still running network-wise
echo -e "\nRemaining network connections:"
ss -tulnp 2>/dev/null | head -20

echo -e "\n========================================"
echo "HOST ISOLATION COMPLETE"
echo "Only Salt master ($SALT_MASTER_IP) can communicate with this host"
echo "========================================"
