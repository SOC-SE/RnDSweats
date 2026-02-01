#!/bin/bash
# ==============================================================================
# Network Audit - Linux
# Comprehensive network security check
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2025-2026
# Improved for Salt-GUI integration
# ==============================================================================

set -euo pipefail

echo "========================================"
echo "NETWORK AUDIT - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/10] LISTENING SERVICES"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tuln | grep LISTEN || echo "No listening services"
elif command -v netstat &>/dev/null; then
    netstat -tuln | grep LISTEN || echo "No listening services"
else
    echo "Neither ss nor netstat available"
fi

echo -e "\n[2/10] ESTABLISHED CONNECTIONS"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tun state established | head -30
    echo "Total established: $(ss -tun state established 2>/dev/null | wc -l)"
else
    netstat -tun 2>/dev/null | grep ESTABLISHED | head -30 || echo "Unable to list connections"
fi

echo -e "\n[3/10] CONNECTIONS BY FOREIGN IP"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tun 2>/dev/null | awk 'NR>1 {print $6}' | cut -d: -f1 | grep -v "^\*$" | sort | uniq -c | sort -rn | head -20 || echo "None"
else
    echo "ss not available"
fi

echo -e "\n[4/10] SUSPICIOUS PORTS (Common Backdoors)"
echo "----------------------------------------"
suspicious_ports=":(4444|5555|6666|7777|1337|31337|12345|54321|9001|9002|8080|8443)"
if command -v ss &>/dev/null; then
    ss -tuln | grep -E "$suspicious_ports" || echo "None found"
else
    netstat -tuln 2>/dev/null | grep -E "$suspicious_ports" || echo "None found"
fi

echo -e "\n[5/10] PROCESSES WITH NETWORK CONNECTIONS"
echo "----------------------------------------"
if command -v ss &>/dev/null; then
    ss -tupn 2>/dev/null | grep -v "^Netid" | head -30 || echo "None or permission denied"
else
    echo "ss not available"
fi

echo -e "\n[6/10] IPTABLES/NFTABLES RULES"
echo "----------------------------------------"
if command -v iptables &>/dev/null; then
    iptables -L -n -v 2>/dev/null | head -40 || echo "iptables not available or permission denied"
elif command -v nft &>/dev/null; then
    nft list ruleset 2>/dev/null | head -40 || echo "nftables not available or permission denied"
else
    echo "Neither iptables nor nftables available"
fi

echo -e "\n[7/10] IP FORWARDING STATUS"
echo "----------------------------------------"
echo "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 'N/A')"
echo "IPv6 forwarding: $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 'N/A')"

echo -e "\n[8/10] ARP TABLE"
echo "----------------------------------------"
if command -v ip &>/dev/null; then
    ip neigh show 2>/dev/null || echo "Unable to show ARP table"
elif command -v arp &>/dev/null; then
    arp -a 2>/dev/null || echo "Unable to show ARP table"
else
    echo "Neither ip nor arp available"
fi

echo -e "\n[9/10] ROUTING TABLE"
echo "----------------------------------------"
if command -v ip &>/dev/null; then
    ip route show 2>/dev/null || echo "Unable to show routes"
else
    route -n 2>/dev/null || echo "Unable to show routes"
fi

echo -e "\n[10/10] DNS CONFIGURATION"
echo "----------------------------------------"
echo "=== /etc/resolv.conf ==="
cat /etc/resolv.conf 2>/dev/null || echo "resolv.conf not found"
echo ""
echo "=== /etc/hosts (non-comments) ==="
grep -v "^#" /etc/hosts 2>/dev/null | grep -v "^$" || echo "hosts file not found"

echo -e "\n========================================"
echo "NETWORK AUDIT COMPLETE"
echo "========================================"
