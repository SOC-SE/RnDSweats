#!/bin/bash
set -euo pipefail  # Fail on errors, unset vars, and pipe failures for reliability

# Define key IP addresses (hardcoded for speed)
WEB_SERVER_IP="172.20.241.30"
MAIL_SERVER_IP="172.20.241.40"
SPLUNK_IP="172.20.241.20"
DEBIAN_DNS_IP="172.20.240.20"
WIN_DNS_IP="172.20.242.200"
WAZUH_MANAGER_IP="172.20.241.20"

# Update package list (idempotent)
apt-get update -y

# Install dependencies if not present (nginx, suricata, iptables-persistent for persistence)
apt-get install -y nginx suricata iptables-persistent curl

# Enable IP forwarding (idempotent via sysctl)
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | tee /etc/sysctl.d/99-ip-forward.conf > /dev/null
sysctl --load=/etc/sysctl.d/99-ip-forward.conf

# Kill-switch: Uncomment and run these to disable all rules and redirection
# iptables -F
# iptables -t nat -F
# iptables-save | tee /etc/iptables/rules.v4 > /dev/null  # Persist empty rules

# Set up iptables rules (idempotent: flush specific chains first, then add)
iptables -F FORWARD  # Clear forward chain for reruns
iptables -F INPUT    # Clear input chain
iptables -t nat -F PREROUTING  # Clear nat prerouting

# ACCEPT all ICMP (competition rule compliance)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT

# Redirect HTTP traffic to local NGINX (port 8080) for WAF
iptables -t nat -A PREROUTING -p tcp --dport 80 -d ${WEB_SERVER_IP} -j REDIRECT --to-port 8080

# Queue scored service traffic to NFQUEUE 0 for Suricata IPS
iptables -A FORWARD -p tcp --dport 25 -d ${MAIL_SERVER_IP} -j NFQUEUE --queue-num 0   # SMTP
iptables -A FORWARD -p tcp --dport 110 -d ${MAIL_SERVER_IP} -j NFQUEUE --queue-num 0  # POP3
iptables -A FORWARD -p tcp --dport 53 -d ${DEBIAN_DNS_IP} -j NFQUEUE --queue-num 0    # DNS TCP
iptables -A FORWARD -p udp --dport 53 -d ${DEBIAN_DNS_IP} -j NFQUEUE --queue-num 0    # DNS UDP
iptables -A FORWARD -p tcp --dport 53 -d ${WIN_DNS_IP} -j NFQUEUE --queue-num 0       # DNS TCP
iptables -A FORWARD -p udp --dport 53 -d ${WIN_DNS_IP} -j NFQUEUE --queue-num 0       # DNS UDP
iptables -A FORWARD -p tcp --dport 8000 -d ${SPLUNK_IP} -j NFQUEUE --queue-num 0      # Splunk GUI

# Queue all other forwarded traffic to NFQUEUE 0 for C2 inspection
iptables -A FORWARD -j NFQUEUE --queue-num 0

# Persist iptables rules
iptables-save | tee /etc/iptables/rules.v4 > /dev/null

# Basic NGINX config for WAF proxy to Web Server (overwrite if exists for idempotency)
cat <<EOF > /etc/nginx/sites-available/default
server {
    listen 8080;
    location / {
        proxy_pass http://${WEB_SERVER_IP}:80;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$host;
    }
}
EOF
systemctl reload nginx || systemctl start nginx

# Configure Suricata in nfqueue mode (edit config idempotently)
sed -i 's/^af-packet:/nfq:\n  - interface: default\n    queue: 0\n    mode: ips/g' /etc/suricata/suricata.yaml || true  # Add if not present
systemctl restart suricata

# Install Wazuh Agent (idempotent: check if installed)
if ! dpkg -l | grep -q wazuh-agent; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update -y
    apt-get install -y wazuh-agent
fi
sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/g" /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent

# Enable services on boot (idempotent)
systemctl enable nginx suricata wazuh-agent netfilter-persistent
