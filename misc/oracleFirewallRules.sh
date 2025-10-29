#!/bin/bash

echo "Flushing all existing iptables rules..."
iptables -F  # Flush all rules
iptables -X  # Delete all user-defined chains
iptables -Z  # Zero all counters

# Drop all incoming traffic by default
iptables -P INPUT DROP
# Drop all forwarded traffic
iptables -P FORWARD DROP
# Allow all outgoing traffic
iptables -P OUTPUT ACCEPT

# Allow traffic on the loopback interface (server talking to itself)
iptables -A INPUT -i lo -j ACCEPT

# Allow established and related connections (the "stateful" part)
# This lets replies to your outgoing connections back in.
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# --- Splunk ---
# Listener for forwarders
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
# Syslog listener (TCP)
iptables -A INPUT -p tcp --dport 514 -j ACCEPT
# Syslog listener (UDP)
iptables -A INPUT -p udp --dport 514 -j ACCEPT

# --- Wazuh ---
# 443 (Dashboard), 1514 (Agents), 1515 (Enrollment), 9200 (Indexer), 55000 (API)
iptables -A INPUT -p tcp -m multiport --dports 443,1514,1515,9200,55000 -j ACCEPT

# --- SaltStack ---
# 4505 (Master Publisher), 4506 (Master Returner)
iptables -A INPUT -p tcp -m multiport --dports 4505,4506 -j ACCEPT
# 8001 (Custom API port), 3000 (Custom WebGUI port)
iptables -A INPUT -p tcp -m multiport --dports 8001,3000 -j ACCEPT


echo "Saving rules..."
# The command to save rules varies by OS distribution.
# For Oracle 9 (RHEL-based), this is the standard way.
service iptables save
# An alternative is: iptables-save > /etc/sysconfig/iptables

echo "iptables rules applied and saved."









# Archive
#
# --- Velociraptor ---
# 8000 (Client Frontend), 8889 (Admin GUI)
#iptables -A INPUT -p tcp -m multiport --dports 8000,8889 -j ACCEPT

