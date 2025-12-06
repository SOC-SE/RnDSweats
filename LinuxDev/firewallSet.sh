#!/bin/bash
# =============================================================================
# CCDC FIREWALL GENERATOR v3
# Features: Docker-Safe, Service-Based, SIEM Support, AUTO-LOGGING CONFIG
# =============================================================================

# --- COLORS & VARIABLES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

EXPORT_FILE="/root/iptables_services.rules"
declare -a TCP_PORTS
declare -a UDP_PORTS

# --- HELPER FUNCTIONS ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root.${NC}"
        exit 1
    fi
}

detect_docker() {
    if command -v docker &> /dev/null && docker ps &> /dev/null; then
        echo -e "${YELLOW}[!] Docker detected! Enabling Safe Mode (Preserving NAT).${NC}"
        DOCKER_SAFE=true
    else
        DOCKER_SAFE=false
    fi
}

# --- LOGGING CONFIGURATION ---

configure_custom_logging() {
    echo -e "\n${BLUE}=== LOGGING CONFIGURATION ===${NC}"
    echo "This will configure rsyslog to divert dropped packet logs to /var/log/firewall.log"
    echo "This makes reading logs for Incident Reports MUCH easier."
    
    if [ -d "/etc/rsyslog.d" ]; then
        echo -e "${GREEN}[*] Detected rsyslog directory.${NC}"
        
        # Create config to redirect specific firewall logs
        cat <<EOF > /etc/rsyslog.d/99-firewall-droplog.conf
:msg, contains, "FW-DROP: " -/var/log/firewall.log
& stop
EOF
        
        echo -e "${GREEN}[*] Restarting rsyslog service...${NC}"
        systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[SUCCESS] Logs will appear in: /var/log/firewall.log${NC}"
            echo -e "          Monitor with: tail -f /var/log/firewall.log"
        else
            echo -e "${YELLOW}[!] Failed to restart rsyslog. Check manually.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] rsyslog not found (common on minimal Fedora/Arch).${NC}"
        echo -e "    Logs will default to 'dmesg' or 'journalctl -k'."
    fi
}

# --- SERVICE SELECTION ---

select_services() {
    echo -e "\n${BLUE}=== CORE INFRASTRUCTURE ===${NC}"
    
    # 1. SSH
    echo -e "${RED}CRITICAL:${NC} If connected via SSH, you MUST say YES."
    read -p "Allow SSH (22)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && TCP_PORTS+=("22")

    # 2. Web Services
    read -p "Allow HTTP/HTTPS (80, 443)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && TCP_PORTS+=("80" "443")

    # 3. DNS
    read -p "Allow DNS Server (53 UDP/TCP)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("53")
        UDP_PORTS+=("53")
    fi

    # 4. FTP (Legacy/Business Task)
    read -p "Allow FTP (20, 21)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("20" "21")
        echo -e "${YELLOW}Note: Loading nf_conntrack_ftp module for Passive FTP support.${NC}"
        modprobe nf_conntrack_ftp 2>/dev/null
    fi

    # 5. NTP
    read -p "Allow NTP Server (123 UDP)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && UDP_PORTS+=("123")

    # 6. Syslog
    read -p "Allow Syslog Ingest (514 UDP/TCP)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("514")
        UDP_PORTS+=("514")
    fi

    echo -e "\n${BLUE}=== LOGGING & SIEM (ELK / SPLUNK) ===${NC}"

    # 7. ELK Stack
    read -p "Is this an ELK SERVER (Kibana 5601, ES 9200, Beats 5044)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && TCP_PORTS+=("5601" "9200" "5044")

    read -p "Is this an ELK AGENT (Filebeat/Metricbeat)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}  > Agent detected. Outbound traffic is allowed by default.${NC}"
    fi

    # 8. Splunk
    read -p "Is this a SPLUNK SERVER/INDEXER (Web 8000, Mgmt 8089, Input 9997, 514)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("8000" "8089" "9997" "514")
        UDP_PORTS+=("514") # Syslog UDP
    fi

    read -p "Is this a SPLUNK FORWARDER (Agent)? [y/N]: " opt
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        read -p "  > Do you need the Deployment Server to manage this agent (Port 8089 IN)? [y/N]: " subopt
        [[ "$subopt" =~ ^[Yy]$ ]] && TCP_PORTS+=("8089")
    fi

    echo -e "\n${BLUE}=== EDR & ACTIVE DEFENSE (WAZUH / VELOCIRAPTOR) ===${NC}"

    # 9. Wazuh
    read -p "Is this a WAZUH SERVER (1514, 1515, 55000, 443)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && TCP_PORTS+=("1514" "1515" "55000" "443")

    read -p "Is this a WAZUH AGENT? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && echo -e "${GREEN}  > Agent outbound traffic allowed.${NC}"

    # 10. Velociraptor
    read -p "Is this a VELOCIRAPTOR SERVER (GUI 8000, Agent 8001, 8003)? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && TCP_PORTS+=("8000" "8001" "8003")

    read -p "Is this a VELOCIRAPTOR AGENT? [y/N]: " opt
    [[ "$opt" =~ ^[Yy]$ ]] && echo -e "${GREEN}  > Agent outbound traffic allowed.${NC}"

    # 11. Custom
    echo -e "\n${BLUE}=== CUSTOM ===${NC}"
    read -p "Enter CUSTOM TCP ports (comma separated): " custom_tcp
    if [[ ! -z "$custom_tcp" ]]; then
        IFS=',' read -ra ADDR <<< "$custom_tcp"
        for i in "${ADDR[@]}"; do TCP_PORTS+=("$i"); done
    fi
    
    read -p "Enter CUSTOM UDP ports (comma separated): " custom_udp
    if [[ ! -z "$custom_udp" ]]; then
        IFS=',' read -ra ADDR <<< "$custom_udp"
        for i in "${ADDR[@]}"; do UDP_PORTS+=("$i"); done
    fi
}

# --- GENERATE & APPLY ---

generate_rules() {
    echo -e "\n${GREEN}[*] Generating Rules...${NC}"
    
    cat <<EOF > $EXPORT_FILE
#!/bin/bash
# CCDC Service-Based Firewall Rule Set v3

EOF

    # FLUSH LOGIC
    if [ "$DOCKER_SAFE" = true ]; then
        echo "# Docker detected - Flushing only user chains" >> $EXPORT_FILE
        cat <<EOF >> $EXPORT_FILE
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -F INPUT
iptables -F FORWARD
# Preserving NAT/DOCKER chains
EOF
    else
        echo "# Standard Flush" >> $EXPORT_FILE
        cat <<EOF >> $EXPORT_FILE
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
EOF
    fi

    # BASELINE
    cat <<EOF >> $EXPORT_FILE

# --- BASELINE ---
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
EOF

    # SERVICES
    echo -e "\n# --- ALLOWED SERVICES ---" >> $EXPORT_FILE
    
    IFS=" " read -r -a UNIQUE_TCP <<< "$(echo "${TCP_PORTS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    IFS=" " read -r -a UNIQUE_UDP <<< "$(echo "${UDP_PORTS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

    for port in "${UNIQUE_TCP[@]}"; do
        echo "iptables -A INPUT -p tcp --dport $port -m conntrack --ctstate NEW -j ACCEPT" >> $EXPORT_FILE
    done

    for port in "${UDP_PORTS[@]}"; do
        echo "iptables -A INPUT -p udp --dport $port -m conntrack --ctstate NEW -j ACCEPT" >> $EXPORT_FILE
    done

    # DOCKER & LOGGING
    if [ "$DOCKER_SAFE" = true ]; then
        echo -e "\n# --- DOCKER ---" >> $EXPORT_FILE
        echo "iptables -A INPUT -i docker0 -j ACCEPT" >> $EXPORT_FILE
    fi

    # LOGGING RULE
    # We set a limit of 10/min to prevent disk-fill DOS attacks, but enough to capture scan data
    cat <<EOF >> $EXPORT_FILE

# --- LOG & DROP ---
iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "FW-DROP: " --log-level 4
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
EOF

    echo -e "${GREEN}[*] Rules written to $EXPORT_FILE${NC}"
    chmod +x $EXPORT_FILE
}

# --- MAIN ---
clear
echo -e "${GREEN}CCDC Firewall Generator v3 (Auto-Logging)${NC}"
check_root
detect_docker
configure_custom_logging
select_services
generate_rules

echo -e "\n${YELLOW}REVIEW:${NC}"
echo "TCP Allow: ${UNIQUE_TCP[*]}"
echo "UDP Allow: ${UNIQUE_UDP[*]}"
echo "Logs will go to: /var/log/firewall.log"

read -p "Apply these rules now? [y/N]: " apply_now
if [[ "$apply_now" =~ ^[Yy]$ ]]; then
    bash $EXPORT_FILE
    echo -e "${GREEN}[*] Rules Applied!${NC}"
else
    echo "Run 'bash $EXPORT_FILE' when ready."
fi