#!/bin/bash
# setup_security_appliance.sh
# Configures Ubuntu 18.04 server as security appliance with IP forwarding, NGINX WAF reverse proxy, Suricata IPS, and iptables rules.
# Assumes running as root. Prioritizes speed and uptime; changes are reversible.

set -e  # Exit on error
set -u  # Treat unset variables as error

# Variables
WEB_SERVER_IP="172.20.241.30"  # CentOS Web Server
MAIL_SERVER_IP="172.20.241.40" # Fedora Mail Server
DNS_DEBIAN_IP="172.20.240.20"  # Debian DNS
DNS_WINDOWS_IP="172.20.242.200" # Windows DNS
SPLUNK_SERVER_IP="172.20.241.20" # Splunk Server
APPLIANCE_IP="172.20.242.10"   # This machine's IP

# Dynamically detect outbound interface
OUT_IFACE=$(ip route | grep default | awk '{print $5}' || echo "eth0")

# Step 1: Update system and install dependencies
apt update -y
apt install -y nginx suricata libnetfilter-queue-dev iptables-persistent

# Step 2: Enable IP forwarding persistently
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p

# Step 3: Configure NGINX as WAF/Reverse Proxy for HTTP
# Backup original config
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak

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

        # Basic WAF rules (expand as needed)
        if (\$request_method !~ ^(GET|HEAD|POST)$) {
            return 444;
        }
    }
}
EOF

# Test and reload NGINX
nginx -t && systemctl reload nginx

# Step 4: Configure Suricata for IPS mode with NFQUEUE
# Backup Suricata config
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Enable NFQ in suricata.yaml (assuming queue 0 for IPS)
sed -i 's/# - nfq/- nfq/' /etc/suricata/suricata.yaml
sed -i '/- nfq:/a \  mode: ips\n  fail-open: yes' /etc/suricata/suricata.yaml  # fail-open to maintain uptime
sed -i 's/af-packet:/#af-packet:/' /etc/suricata/suricata.yaml  # Disable af-packet if conflicting

# Update rules (assuming emerging threats or similar; adjust if needed)
suricata-update

# Restart Suricata
systemctl restart suricata

# Step 5: Set up iptables rules
# Flush existing rules for clean setup (be cautious in production)
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Permit all ICMP traffic (required by competition rules)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

# Redirect HTTP (80) to local NGINX (already listening on 80, but ensure forwarding if needed)
# Since NGINX is on this machine, no redirect needed; Palo Alto sends to this IP:80

# For other protocols, redirect to NFQUEUE for Suricata inspection (queue 0)
# SMTP (25) to Mail Server via NFQUEUE
iptables -A FORWARD -d $MAIL_SERVER_IP -p tcp --dport 25 -j NFQUEUE --queue-num 0

# POP3 (110) to Mail Server via NFQUEUE
iptables -A FORWARD -d $MAIL_SERVER_IP -p tcp --dport 110 -j NFQUEUE --queue-num 0

# DNS TCP/53 to DNS servers via NFQUEUE
iptables -A FORWARD -d $DNS_DEBIAN_IP -p tcp --dport 53 -j NFQUEUE --queue-num 0
iptables -A FORWARD -d $DNS_WINDOWS_IP -p tcp --dport 53 -j NFQUEUE --queue-num 0

# DNS UDP/53 to DNS servers via NFQUEUE
iptables -A FORWARD -d $DNS_DEBIAN_IP -p udp --dport 53 -j NFQUEUE --queue-num 0
iptables -A FORWARD -d $DNS_WINDOWS_IP -p udp --dport 53 -j NFQUEUE --queue-num 0

# Splunk GUI (8000) to Splunk Server via NFQUEUE
iptables -A FORWARD -d $SPLUNK_SERVER_IP -p tcp --dport 8000 -j NFQUEUE --queue-num 0

# Allow forwarding for egress from protected servers (assuming they use this as gateway)
iptables -A FORWARD -s 172.20.240.0/24 -j ACCEPT  # Internal LAN
iptables -A FORWARD -s 172.20.241.0/24 -j ACCEPT  # Public LAN
iptables -A FORWARD -s 172.20.242.0/24 -j ACCEPT  # User LAN

# NAT for outbound traffic (masquerade)
iptables -t nat -A POSTROUTING -o $OUT_IFACE -j MASQUERADE

# Default policies
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP  # Drop by default, only allow specified

# Save iptables rules persistently
netfilter-persistent save

echo "Security Appliance configuration complete. Verify services and rules."
