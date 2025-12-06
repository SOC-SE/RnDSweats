#!/bin/bash
# =============================================================================
# UNIVERSAL SENTINEL FIREWALL v10
# Logic: Full Interactive Menu | Granular Agents | K8s Manual/Auto | Logging
# =============================================================================

# --- GLOBAL VARS ---
declare -a TCP_PORTS
declare -a UDP_PORTS
IS_K8S=false
IS_DOCKER=false
MOD_FTP=false
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/firewall.log"

# --- HELPER FUNCTIONS ---

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "--- CORE ---"
    echo "  -h, --help        Show this help"
    echo "  --ssh             Allow SSH (22)"
    echo "  --persist         Save rules across reboots"
    echo ""
    echo "--- INFRASTRUCTURE ---"
    echo "  --web             HTTP/HTTPS (80, 443)"
    echo "  --dns             DNS (53 TCP/UDP)"
    echo "  --ntp             NTP Server (123 UDP)"
    echo "  --ftp             FTP (20, 21)"
    echo "  --mail            SMTP/IMAP/POP3 (25, 465, 587, 110, 143, 993, 995)"
    echo "  --db-mysql        MySQL/MariaDB (3306)"
    echo "  --db-postgres     PostgreSQL (5432)"
    echo "  --smb             Samba/Windows Share (139, 445)"
    echo "  --k8s             Kubernetes API/Kubelet (6443, 10250)"
    echo ""
    echo "--- DEFENSIVE TOOLS ---"
    echo "  --splunk-srv      Splunk Enterprise (8000, 8089, 9997, 514)"
    echo "  --splunk-fwd      Splunk Forwarder Mgmt (8089)"
    echo "  --wazuh-srv       Wazuh Manager/API (1514, 1515, 55000, 443)"
    echo "  --wazuh-agt       Wazuh Agent (Outbound allowed by default)"
    echo "  --velo-srv        Velociraptor Server (8000, 8001, 8003)"
    echo "  --velo-agt        Velociraptor Agent (Outbound allowed by default)"
    echo "  --salt-master     Salt Master (4505, 4506, 8881-API, 3000-GUI)"
    echo "  --salt-minion     Salt Minion (Outbound allowed by default)"
    echo ""
    echo "--- MISC ---"
    echo "  --minecraft       Minecraft Server (25565)"
    echo "  --custom-tcp      Comma separated list (e.g. 8080,4444)"
    echo ""
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] Error: This script must be run as root."
        exit 1
    fi
}

# --- DETECTION & PREP ---

prepare_os() {
    echo "[*] Detecting Package Manager..."
    
    # Check for DNF or YUM (RHEL/Fedora/CentOS/Rocky)
    if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        echo "    > Detected RPM-based system (dnf/yum)."
        if systemctl is-active --quiet firewalld; then
            echo "    > Disabling firewalld..."
            systemctl stop firewalld
            systemctl disable firewalld
            systemctl mask firewalld
        fi
        if ! rpm -q iptables-services &> /dev/null; then
            echo "    > Installing iptables-services..."
            if command -v dnf &> /dev/null; then dnf install -y iptables-services; else yum install -y iptables-services; fi
        fi
        systemctl enable iptables

    # Check for APT (Debian/Ubuntu/Kali)
    elif command -v apt-get &> /dev/null; then
        echo "    > Detected DEB-based system (apt)."
        if ! dpkg -s iptables-persistent &> /dev/null; then
            echo "    > Installing iptables-persistent..."
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
        fi
    fi
}

configure_logging() {
    echo "[*] Configuring Active Defense Logging..."
    if [ ! -d "$LOG_DIR" ]; then mkdir -p "$LOG_DIR"; fi
    if [ -d "/etc/rsyslog.d" ]; then
        cat <<EOF > /etc/rsyslog.d/99-defensive-firewall.conf
:msg, contains, "FW-DROP" -${LOG_FILE}
& stop
EOF
        systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null
    fi
    echo "    > Logs targeted at: $LOG_FILE"
}

detect_orchestration() {
    # Check binaries/interfaces but respect manual override if already set
    if [ "$IS_K8S" = false ]; then
        if command -v kubelet &> /dev/null || ip link show | grep -qE "cni|flannel|calico|cilium"; then
            echo -e "\033[1;33m[!] KUBERNETES DETECTED (Auto). Engaging Safe-Flush Mode.\033[0m"
            IS_K8S=true
            TCP_PORTS+=("6443" "10250" "10255")
            UDP_PORTS+=("8472") 
        fi
    fi

    if [ "$IS_DOCKER" = false ]; then
        if command -v docker &> /dev/null && docker ps &> /dev/null; then
            echo -e "\033[1;33m[!] DOCKER DETECTED (Auto). Preserving NAT.\033[0m"
            IS_DOCKER=true
        fi
    fi
}

# --- MODES ---

interactive_menu() {
    clear
    echo "=== UNIVERSAL SENTINEL CONFIG V10 ==="
    echo "--- BASIC ACCESS ---"
    
    read -p "1. Allow SSH (22)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || TCP_PORTS+=("22") # Default Yes

    read -p "2. Allow Web (80/443)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("80" "443")

    read -p "3. Allow DNS Server (53)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then TCP_PORTS+=("53"); UDP_PORTS+=("53"); fi

    read -p "4. Allow NTP Server (123 UDP)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && UDP_PORTS+=("123")

    read -p "5. Allow Mail (SMTP/IMAP/POP3)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("25" "465" "587" "110" "143" "993" "995")

    read -p "6. Allow FTP (20/21)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("20" "21") && MOD_FTP=true

    read -p "7. Allow SMB/Samba (139/445)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("139" "445")

    echo -e "\n--- SECURITY TOOLS (Server vs Agent) ---"
    
    # SPLUNK
    read -p "8. Is this a SPLUNK SERVER (Indexer/Web)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then 
        TCP_PORTS+=("8000" "8089" "9997" "514"); UDP_PORTS+=("514")
    else
        read -p "   > Is this a Splunk FORWARDER? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && TCP_PORTS+=("8089") && echo "     (Allowed Mgmt Port 8089)"
    fi

    # WAZUH
    read -p "9. Is this a WAZUH SERVER (Manager)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("1514" "1515" "55000" "443")
    else
        read -p "   > Is this a Wazuh AGENT? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && echo "     (Agent Outbound Allowed by Default)"
    fi

    # VELOCIRAPTOR
    read -p "10. Is this a VELOCIRAPTOR SERVER? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("8000" "8001" "8003")
    else
        read -p "    > Is this a Velociraptor AGENT? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && echo "      (Agent Outbound Allowed by Default)"
    fi

    # SALT
    read -p "11. Is this a SALT MASTER (4505/4506, API-8881, GUI-3000)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        TCP_PORTS+=("4505" "4506" "8881" "3000")
    else
        read -p "    > Is this a Salt MINION? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && echo "      (Minion Outbound Allowed by Default)"
    fi

    echo -e "\n--- INFRASTRUCTURE ---"
    read -p "12. Is this a KUBERNETES NODE (Force Enable)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        IS_K8S=true
        TCP_PORTS+=("6443" "10250")
        echo "    (K8s Safe-Flush Enabled)"
    fi

    read -p "13. Allow Databases (MySQL 3306 / Postgres 5432)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("3306" "5432")
    
    read -p "14. Allow Minecraft (25565)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && TCP_PORTS+=("25565") && UDP_PORTS+=("25565")

    echo -e "\n--- FINALIZE ---"
    read -p "15. Enable Persistence? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || PERSIST=true # Default Yes
}

parse_args() {
    while [ "$1" != "" ]; do
        case $1 in
            -h | --help )       usage ;;
            # Core
            --ssh )             TCP_PORTS+=("22") ;;
            --web )             TCP_PORTS+=("80" "443") ;;
            --dns )             TCP_PORTS+=("53"); UDP_PORTS+=("53") ;;
            --ntp )             UDP_PORTS+=("123") ;;
            --ftp )             TCP_PORTS+=("20" "21"); MOD_FTP=true ;;
            --mail )            TCP_PORTS+=("25" "465" "587" "110" "143" "993" "995") ;;
            --smb )             TCP_PORTS+=("139" "445") ;;
            # Databases
            --db-mysql )        TCP_PORTS+=("3306") ;;
            --db-postgres )     TCP_PORTS+=("5432") ;;
            # Security
            --splunk-srv )      TCP_PORTS+=("8000" "8089" "9997" "514"); UDP_PORTS+=("514") ;;
            --splunk-fwd )      TCP_PORTS+=("8089") ;;
            --wazuh-srv )       TCP_PORTS+=("1514" "1515" "55000" "443") ;;
            --wazuh-agt )       echo "Info: Wazuh Agent outbound is allowed by default." ;;
            --velo-srv )        TCP_PORTS+=("8000" "8001" "8003") ;;
            --velo-agt )        echo "Info: Velociraptor Agent outbound is allowed by default." ;;
            --salt-master )     TCP_PORTS+=("4505" "4506" "8881" "3000") ;;
            --salt-minion )     echo "Info: Salt Minion outbound is allowed by default." ;;
            # Misc
            --minecraft )       TCP_PORTS+=("25565"); UDP_PORTS+=("25565") ;;
            --k8s )             IS_K8S=true; TCP_PORTS+=("6443" "10250") ;;
            --custom-tcp )      shift; IFS=',' read -ra ADDR <<< "$1"; for i in "${ADDR[@]}"; do TCP_PORTS+=("$i"); done ;;
            --persist )         PERSIST=true ;;
        esac
        shift
    done
}

# --- FIREWALL EXECUTION ---

apply_rules() {
    echo "[*] Applying Rules..."
    
    # Load Kernel Modules if needed
    if [ "$MOD_FTP" = true ]; then modprobe nf_conntrack_ftp 2>/dev/null; fi

    # 1. FAIL-SAFE: ACCEPT ALL
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # 2. SAFE FLUSH (K8s/Docker Protection)
    if [ "$IS_K8S" = true ] || [ "$IS_DOCKER" = true ]; then
        iptables -F INPUT
        # Do not flush NAT or MANGLE tables on Orchestrators
    else
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
    fi

    # 3. IPv6 SOFT-LOCK (Drop All, But don't break kernel)
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # 4. BASELINE (Localhost & ICMP Allowed)
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT

    # 5. ORCHESTRATION WHITELIST
    if [ "$IS_K8S" = true ]; then
        # Allow CNI interfaces (Pod-to-Pod)
        iptables -A INPUT -i cni+ -j ACCEPT
        iptables -A INPUT -i flannel+ -j ACCEPT
        iptables -A INPUT -i calico+ -j ACCEPT
        iptables -A INPUT -i cilium+ -j ACCEPT
        iptables -A INPUT -i tunl0 -j ACCEPT
        iptables -A INPUT -p vrrp -j ACCEPT
    fi
    if [ "$IS_DOCKER" = true ]; then
        iptables -A INPUT -i docker0 -j ACCEPT
    fi

    # 6. ALLOW SERVICES
    # Sort and remove duplicates
    IFS=" " read -r -a UNIQUE_TCP <<< "$(echo "${TCP_PORTS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    IFS=" " read -r -a UNIQUE_UDP <<< "$(echo "${UDP_PORTS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

    for port in "${UNIQUE_TCP[@]}"; do
        if [ ! -z "$port" ]; then
            iptables -A INPUT -p tcp --dport $port -m conntrack --ctstate NEW -j ACCEPT
        fi
    done

    for port in "${UDP_PORTS[@]}"; do
        if [ ! -z "$port" ]; then
            iptables -A INPUT -p udp --dport $port -m conntrack --ctstate NEW -j ACCEPT
        fi
    done

    # 7. LOGGING (Active Defense)
    # Log to kernel with prefix, rsyslog will catch this and move to firewall.log
    iptables -A INPUT -m limit --limit 5/sec -j LOG --log-prefix "FW-DROP: " --log-level 4
    
    # 8. DROP
    iptables -A INPUT -j DROP
    
    # Only drop FORWARD if not an Orchestrator
    if [ "$IS_K8S" = false ] && [ "$IS_DOCKER" = false ]; then
        iptables -P FORWARD DROP
    fi
}

save_persistence() {
    if [ "$PERSIST" = true ]; then
        echo "[*] Saving Persistence..."
        # RPM-Based
        if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
            service iptables save
            # Backup IPv6 just in case
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null
        # DEB-Based
        elif command -v apt-get &> /dev/null; then
            netfilter-persistent save
        # Generic Fallback
        else
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        fi
        echo "    > Rules saved."
    fi
}

# --- RUNTIME ---
check_root
prepare_os
configure_logging

if [ $# -eq 0 ]; then
    interactive_menu
else
    parse_args "$@"
fi

detect_orchestration
apply_rules
save_persistence

echo -e "\n[+] FIREWALL APPLIED."
echo -e "    Logs: $LOG_FILE"
echo -e "    IPv6: Dropped (Enabled in Kernel)"