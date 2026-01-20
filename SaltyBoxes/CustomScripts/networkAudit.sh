#!/bin/bash
# ==============================================================================
# Network Audit - Linux
# Comprehensive network security check
# ==============================================================================

echo "========================================"
echo "NETWORK AUDIT - $(hostname)"
echo "Time: $(date)"
echo "========================================"

echo -e "\n[1/10] LISTENING SERVICES"
echo "----------------------------------------"
ss -tuln | grep LISTEN
echo ""
netstat -tuln 2>/dev/null | grep LISTEN || true

echo -e "\n[2/10] ESTABLISHED CONNECTIONS"
echo "----------------------------------------"
ss -tun state established | head -30
echo "Total established: $(ss -tun state established | wc -l)"

echo -e "\n[3/10] CONNECTIONS BY FOREIGN IP"
echo "----------------------------------------"
ss -tun | awk 'NR>1 {print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

echo -e "\n[4/10] SUSPICIOUS PORTS (Common Backdoors)"
echo "----------------------------------------"
ss -tuln | grep -E ":(4444|5555|6666|7777|1337|31337|12345|54321|9001|9002|8080|8443)" || echo "None found"

echo -e "\n[5/10] PROCESSES WITH NETWORK CONNECTIONS"
echo "----------------------------------------"
ss -tupn | grep -v "^Netid" | head -30

echo -e "\n[6/10] IPTABLES RULES"
echo "----------------------------------------"
iptables -L -n -v 2>/dev/null | head -40 || echo "iptables not available"

echo -e "\n[7/10] IP FORWARDING STATUS"
echo "----------------------------------------"
echo "IPv4 forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "IPv6 forwarding: $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 'N/A')"

echo -e "\n[8/10] ARP TABLE"
echo "----------------------------------------"
arp -a 2>/dev/null || ip neigh show

echo -e "\n[9/10] ROUTING TABLE"
echo "----------------------------------------"
ip route show

echo -e "\n[10/10] DNS CONFIGURATION"
echo "----------------------------------------"
cat /etc/resolv.conf
echo ""
cat /etc/hosts | grep -v "^#" | grep -v "^$"

echo -e "\n========================================"
echo "NETWORK AUDIT COMPLETE"
echo "========================================"
