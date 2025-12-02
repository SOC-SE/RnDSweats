#!/bin/bash
# SaltStack Diagnostic Agent
# Run this on the Master to gather debug info

echo "=== OS Information ==="
cat /etc/os-release | grep PRETTY_NAME
uname -r

echo -e "\n=== Crypto Policy ==="
update-crypto-policies --show

echo -e "\n=== Python Crypto Libraries ==="
pip3 list | grep -E "crypto|M2Crypto"

echo -e "\n=== Salt Versions ==="
salt --versions-report

echo -e "\n=== Master Config (Sensitive Info Redacted) ==="
grep -vE "password|token|user" /etc/salt/master | grep -E "interface|hash_type|worker_threads|auto_accept"

echo -e "\n=== Firewalld Status ==="
systemctl status firewalld | grep Active
firewall-cmd --list-ports 2>/dev/null

echo -e "\n=== Connection Test (Listening Ports) ==="
ss -tulnp | grep -E "4505|4506"

echo -e "\n=== Recent Master Errors ==="
journalctl -u salt-master --no-pager -n 20 | grep -E "Error|Exception|denied"

echo -e "\n=== Minion Key Status ==="
salt-key -L