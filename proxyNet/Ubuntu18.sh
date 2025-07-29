#!/bin/bash
# setup_security_appliance.sh
# EDITED: Now stops and disables apache2 if it is running.
# EDITED: Implemented JA4+ fingerprinting and added the abuse.ch JA4+ ruleset.
# Configures Ubuntu 18.04 server as a security appliance with IP forwarding, NGINX WAF reverse proxy, and Suricata IPS.
# Assumes running as root. Prioritizes speed and uptime; changes are reversible.

set -e  # Exit on error
set -u  # Treat unset variables as error

# --- Variables ---
WEB_SERVER_IP="172.20.241.30"    # CentOS Web Server
MAIL_SERVER_IP="172.20.241.40"   # Fedora Mail Server
DNS_DEBIAN_IP="172.20.240.20"    # Debian DNS
DNS_WINDOWS_IP="172.20.242.200"  # Windows DNS
SPLUNK_SERVER_IP="172.20.241.20" # Splunk Server
OUT_IFACE=$(ip route | grep default | awk '{print $5}' || echo "eth0")

# --- Step 1: Update system and install LATEST Suricata ---
echo "INFO: Installing dependencies and latest Suricata from PPA..."
apt-get update -y
# Install software-properties-common to manage repositories
apt-get install -y software-properties-common

# Add the official Suricata PPA to get version 7.x or newer
add-apt-repository ppa:oisf/suricata-stable -y
apt-get update -y

# Install NGINX, Suricata, and other tools
apt-get install -y nginx suricata libnetfilter-queue-dev iptables-persistent

# --- Step 2: Enable IP forwarding persistently ---
echo "INFO: Enabling IP Forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p

# --- Step 2.5: Ensure Port 80 is Free ---
echo "INFO: Checking for and stopping apache2 service..."
if systemctl is-active --quiet apache2; then
    echo "INFO: Apache2 is active. Stopping and disabling it now."
    systemctl stop apache2
    systemctl disable apache2
else
    echo "INFO: Apache2 service not found or is inactive. No action needed."
fi

# --- Step 3: Configure NGINX as WAF/Reverse Proxy for HTTP ---
echo "INFO: Configuring NGINX as reverse proxy..."
# Create reverse proxy config for HTTP to Web Server
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://$WEB_SERVER_IP:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Test and reload NGINX
nginx -t && systemctl start nginx

# --- Step 4: Configure Suricata for IPS mode with NFQUEUE ---
echo "INFO: Configuring Suricata for IPS mode..."
# Configure Suricata to listen on NFQUEUE 0 in IPS mode
# This uses fail-open to prioritize uptime, as required.
sed -i 's/- nfq/#- nfq/g' /etc/suricata/suricata.yaml # Comment out any existing nfq
sed -i '/# - nfq/a \
- nfq:\n\
    mode: ips\n\
    queue: 0\n\
    fail-open: yes' /etc/suricata/suricata.yaml

# Disable af-packet to prevent conflicts with NFQUEUE
sed -i '/- interface: eth0/,$ s/^/#/' /etc/suricata/suricata.yaml

# --- Step 4.5: Enable JA4+ and Add External Rulesets ---
echo "INFO: Enabling JA4+ fingerprinting in Suricata..."

# Enable JA4/S (TLS) and JA4H (HTTP) in the Suricata config by changing 'no' to 'yes'
sed -i 's/ja4-fingerprints: no/ja4-fingerprints: yes/' /etc/suricata/suricata.yaml
sed -i 's/ja4h-fingerprint: no/ja4h-fingerprint: yes/' /etc/suricata/suricata.yaml

# Ensure local.rules is loaded by Suricata by uncommenting it
sed -i 's/#- local.rules/- local.rules/' /etc/suricata/suricata.yaml

# Add a sample JA4 rule to local.rules to detect a known Cobalt Strike fingerprint
echo 'alert tls any any -> any any (msg:"ET POLICY Cobalt Strike JA4 Hash Observed (e145c3b5a7a401c680f433989f55e5c6)"; tls.ja4.hash; content:"e145c3b5a7a401c680f433989f55e5c6"; classtype:trojan-activity; sid:9000002; rev:1;)' > /etc/suricata/rules/local.rules

# Add the abuse.ch JA4+ fingerprint blacklist if it's not already present
echo "INFO: Adding abuse.ch JA4+ ruleset for Suricata..."
if ! suricata-update list-sources | grep -q "ja4-abuse-ch"; then
    suricata-update add-source ja4-abuse-ch "https://sslbl.abuse.ch/ja4/ja4_rules.tar.gz"
else
    echo "INFO: abuse.ch JA4+ ruleset already configured."
fi

# --- Step 5: Update Rules and Restart Suricata ---
echo "INFO: Updating rule sets (including abuse.ch) and restarting Suricata..."
# Update rules from all configured sources
suricata-update

# Restart Suricata to apply all configuration changes and check status
systemctl restart suricata && systemctl status suricata --no-pager

# --- Step 6: Set up reliable iptables rules ---
echo "INFO: Configuring iptables rules..."
# Flush existing rules for a clean setup
iptables -F
iptables -t nat -F

# Set default FORWARD policy to DROP for security
iptables -P FORWARD DROP

# --- FORWARD Chain Rules (processed in order) ---
# 1. Allow return traffic for established connections (CRITICAL for two-way communication)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. Allow all ICMP traffic (required by competition rules)
iptables -A FORWARD -p icmp -j ACCEPT

# 3. Queue specific new connections to Suricata for inspection
# SMTP (25)
iptables -A FORWARD -d $MAIL_SERVER_IP -p tcp --dport 25 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
# POP3 (110)
iptables -A FORWARD -d $MAIL_SERVER_IP -p tcp --dport 110 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
# DNS (TCP/53)
iptables -A FORWARD -d $DNS_DEBIAN_IP -p tcp --dport 53 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
iptables -A FORWARD -d $DNS_WINDOWS_IP -p tcp --dport 53 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
# DNS (UDP/53)
iptables -A FORWARD -d $DNS_DEBIAN_IP -p udp --dport 53 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
iptables -A FORWARD -d $DNS_WINDOWS_IP -p udp --dport 53 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
# Splunk GUI (8000)
iptables -A FORWARD -d $SPLUNK_SERVER_IP -p tcp --dport 8000 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0

# --- NAT Configuration ---
# NAT for outbound traffic from your internal networks
iptables -t nat -A POSTROUTING -o $OUT_IFACE -j MASQUERADE

# Save iptables rules persistently
netfilter-persistent save

echo "Security Appliance configuration complete. Verify services and rules."
