#!/bin/bash
# =============================================================================
# UNIVERSAL SENTINEL FIREWALL v13 (The "Full Arsenal" Edition)
# Logic: Strict In/Out | Full Service List | Failsafe | K8s Safe
# =============================================================================

# --- GLOBAL VARS ---
declare -a IN_TCP
declare -a IN_UDP
declare -a OUT_TCP
declare -a OUT_UDP

IS_K8S=false
IS_DOCKER=false
MOD_FTP=false
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/firewall.log"
FAILSAFE_DELAY=60

# --- HELPER FUNCTIONS ---

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "--- CORE (OUTBOUND ESSENTIALS) ---"
    echo "  -h, --help        Show this help"
    echo "  --ssh             Allow SSH (In: 22)"
    echo "  --updates         Allow Repo Updates (Out: 80, 443)"
    echo "  --dns-resolver    Allow DNS Lookup (Out: 53)"
    echo "  --ntp-client      Allow Time Sync (Out: 123)"
    echo "  --persist         Save rules across reboots"
    echo ""
    echo "--- INFRASTRUCTURE (INBOUND) ---"
    echo "  --web             HTTP/HTTPS (80, 443)"
    echo "  --dns-server      DNS Server (53 TCP/UDP)"
    echo "  --ftp             FTP (20, 21) + Kernel Modules"
    echo "  --mail            SMTP/IMAP/POP3 (25, 465, 587, 110, 143, 993, 995)"
    echo "  --ldap            LDAP/LDAPS (389, 636 TCP)"
    echo "  --kerb            Kerberos (88 TCP/UDP)"
    echo "  --smb             Samba/Windows Share (139, 445)"
    echo "  --nfs             NFS (2049 TCP/UDP)"
    echo "  --k8s             Kubernetes API/Kubelet (6443, 10250)"
    echo ""
    echo "--- DATABASES (INBOUND) ---"
    echo "  --db-mysql        MySQL/MariaDB (3306)"
    echo "  --db-postgres     PostgreSQL (5432)"
    echo ""
    echo "--- DEFENSIVE TOOLS (SERVER = INBOUND) ---"
    echo "  --splunk-srv      Splunk Enterprise (8000, 8089, 9997, 514)"
    echo "  --wazuh-srv       Wazuh Manager/API (1514, 1515, 55000, 443)"
    echo "  --elk             Elasticsearch/Logstash (9200, 9300, 5044)"
    echo "  --velo-srv        Velociraptor Server (8000, 8001, 8003)"
    echo "  --salt-master     Salt Master (4505, 4506, 8881-API, 3000-GUI)"
    echo "  --palo            Palo Alto Mgmt (443, 22)"
    echo ""
    echo "--- DEFENSIVE AGENTS (AGENT = OUTBOUND) ---"
    echo "  --splunk-fwd      Splunk Forwarder (Out: 8089, 9997)"
    echo "  --wazuh-agt       Wazuh Agent (Out: 1514, 1515)"
    echo "  --velo-agt        Velociraptor Agent (Out: 8001)"
    echo "  --salt-minion     Salt Minion (Out: 4505, 4506)"
    echo ""
    echo "--- MISC ---"
    echo "  --minecraft       Minecraft Server (25565)"
    echo "  --custom-in       Comma separated (e.g. 8080,4444)"
    echo "  --custom-out      Comma separated (e.g. 8.8.8.8,1.1.1.1)"
    echo ""
    exit 0
}

check_root() {
    [[ $EUID -ne 0 ]] && echo "[-] Error: Run as root." && exit 1
}

# --- DETECTION & PREP ---

prepare_os() {
    echo "[*] Detecting Package Manager..."
    if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        if systemctl is-active --quiet firewalld; then
            systemctl stop firewalld; systemctl disable firewalld; systemctl mask firewalld
        fi
        rpm -q iptables-services &> /dev/null || yum install -y iptables-services
        systemctl enable iptables
    elif command -v apt-get &> /dev/null; then
        dpkg -s iptables-persistent &> /dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
    fi
}

configure_logging() {
    if [ ! -d "$LOG_DIR" ]; then mkdir -p "$LOG_DIR"; fi
    if [ -d "/etc/rsyslog.d" ] && command -v rsyslogd &> /dev/null; then
        echo ':msg, contains, "FW-DROP" -'"$LOG_FILE" > /etc/rsyslog.d/99-defensive-firewall.conf
        echo '& stop' >> /etc/rsyslog.d/99-defensive-firewall.conf
        systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null
    fi
}

detect_orchestration() {
    if [ "$IS_K8S" = false ]; then
        if command -v kubelet &> /dev/null || ip link show | grep -qE "cni|flannel|calico|cilium"; then
            echo -e "\033[1;33m[!] KUBERNETES DETECTED. Engaging Safe-Flush & CNI Whitelisting.\033[0m"
            IS_K8S=true
            IN_TCP+=("6443" "10250"); IN_UDP+=("8472")
        fi
    fi
    if [ "$IS_DOCKER" = false ]; then
        if command -v docker &> /dev/null && docker ps &> /dev/null; then
            echo -e "\033[1;33m[!] DOCKER DETECTED. Preserving NAT/FORWARD chains.\033[0m"
            IS_DOCKER=true
        fi
    fi
}

# --- MODES ---

interactive_menu() {
    clear
    echo "=== UNIVERSAL SENTINEL CONFIG v13 (Full Arsenal) ==="
    
    echo "--- BASIC ACCESS (Bidirectional) ---"
    read -p "1. Allow SSH (22)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || IN_TCP+=("22") # Default Yes

    read -p "2. Allow DNS Resolution (Outbound 53)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || { OUT_UDP+=("53"); OUT_TCP+=("53"); }

    read -p "3. Allow System Updates (Outbound 80/443)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_TCP+=("80" "443")

    read -p "4. Allow NTP Sync (Outbound 123)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_UDP+=("123")

    echo -e "\n--- COMMON SERVICES (Server = Inbound) ---"
    read -p "5. Web Server (80/443)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && IN_TCP+=("80" "443")

    read -p "6. Mail Server (SMTP/IMAP/POP3)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && IN_TCP+=("25" "465" "587" "110" "143" "993" "995")

    read -p "7. FTP Server (20/21)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("20" "21"); MOD_FTP=true; }

    read -p "8. SMB/Windows Share (139/445)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && IN_TCP+=("139" "445")

    echo -e "\n--- INFRASTRUCTURE (Server = Inbound) ---"
    read -p "9. DNS Server (53)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("53"); IN_UDP+=("53"); }

    read -p "10. Directory Services (LDAP 389/636, Kerberos 88)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("389" "636" "88"); IN_UDP+=("88"); }

    read -p "11. Database (MySQL 3306 / PG 5432)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && IN_TCP+=("3306" "5432")
    
    read -p "12. NFS Share (2049)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("2049"); IN_UDP+=("2049"); }

    echo -e "\n--- SECURITY TOOLS (Server vs Agent) ---"
    read -p "13. Is this a SPLUNK/WAZUH/ELK SERVER? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        echo "    > Enabling Server Ports (Splunk, Wazuh, ELK, Salt)..."
        IN_TCP+=("8000" "8089" "9997" "514" "1514" "1515" "55000" "443" "9200" "9300" "5601" "4505" "4506")
        IN_UDP+=("514")
    else
        read -p "    > Allow Outbound AGENT Traffic (Splunk/Wazuh/Salt)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("9997" "8089" "1514" "1515" "4505" "4506")
    fi

    echo -e "\n--- MISC ---"
    read -p "14. Minecraft Server (25565)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("25565"); IN_UDP+=("25565"); }

    echo -e "\n--- FINALIZE ---"
    read -p "15. Enable Persistence? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || PERSIST=true
}

parse_args() {
    while [ "$1" != "" ]; do
        case $1 in
            -h | --help )       usage ;;
            # Outbound Essentials
            --ssh )             IN_TCP+=("22") ;;
            --updates )         OUT_TCP+=("80" "443") ;;
            --dns-resolver )    OUT_UDP+=("53"); OUT_TCP+=("53") ;;
            --ntp-client )      OUT_UDP+=("123") ;;
            
            # Inbound Infrastructure
            --web )             IN_TCP+=("80" "443") ;;
            --dns-server )      IN_TCP+=("53"); IN_UDP+=("53") ;;
            --ftp )             IN_TCP+=("20" "21"); MOD_FTP=true ;;
            --mail )            IN_TCP+=("25" "465" "587" "110" "143" "993" "995") ;;
            --ldap )            IN_TCP+=("389" "636") ;;
            --kerb )            IN_TCP+=("88"); IN_UDP+=("88") ;;
            --smb )             IN_TCP+=("139" "445") ;;
            --nfs )             IN_TCP+=("2049"); IN_UDP+=("2049") ;;
            --db-mysql )        IN_TCP+=("3306") ;;
            --db-postgres )     IN_TCP+=("5432") ;;

            # Security SERVERS (Inbound)
            --splunk-srv )      IN_TCP+=("8000" "8089" "9997" "514"); IN_UDP+=("514") ;;
            --wazuh-srv )       IN_TCP+=("1514" "1515" "55000" "443") ;;
            --elk )             IN_TCP+=("9200" "9300" "5601" "5044") ;;
            --velo-srv )        IN_TCP+=("8000" "8001" "8003") ;;
            --salt-master )     IN_TCP+=("4505" "4506" "8881" "3000") ;;
            --palo )            IN_TCP+=("443" "22") ;;

            # Security AGENTS (Outbound)
            --splunk-fwd )      OUT_TCP+=("9997" "8089") ;;
            --wazuh-agt )       OUT_TCP+=("1514" "1515") ;;
            --velo-agt )        OUT_TCP+=("8001") ;;
            --salt-minion )     OUT_TCP+=("4505" "4506") ;;

            # Misc
            --minecraft )       IN_TCP+=("25565"); IN_UDP+=("25565") ;;
            --k8s )             IS_K8S=true; IN_TCP+=("6443" "10250") ;;
            
            --persist )         PERSIST=true ;;
            --custom-in )       shift; IFS=',' read -ra ADDR <<< "$1"; for i in "${ADDR[@]}"; do IN_TCP+=("$i"); done ;;
            --custom-out )      shift; IFS=',' read -ra ADDR <<< "$1"; for i in "${ADDR[@]}"; do OUT_TCP+=("$i"); done ;;
        esac
        shift
    done
}

# --- FAILSAFE ---
start_failsafe() {
    echo -e "\033[1;31m [!] FAILSAFE TIMER: Reverting in $FAILSAFE_DELAY seconds unless confirmed...\033[0m"
    (
        sleep $FAILSAFE_DELAY
        iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -F
        echo " [!!!] FAILSAFE TRIGGERED [!!!]" | wall
    ) &
    FAILSAFE_PID=$!
}

confirm_failsafe() {
    echo ""
    read -t $FAILSAFE_DELAY -p "Apply Permanent? (y/N): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        kill $FAILSAFE_PID 2>/dev/null
        echo -e "[+] Configuration Confirmed."
    else
        echo -e "[!] Reverting..."
    fi
}

# --- FIREWALL LOGIC ---

apply_rules() {
    echo "[*] Applying Rules..."
    
    if [ "$MOD_FTP" = true ]; then 
        modprobe nf_conntrack_ftp 2>/dev/null || echo "    > Warning: Could not load FTP conntrack."
    fi

    # 1. SET POLICY TO ACCEPT (Prevent instant lockout)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # 2. FLUSH
    if [ "$IS_K8S" = true ] || [ "$IS_DOCKER" = true ]; then
        iptables -F INPUT; iptables -F OUTPUT
    else
        iptables -F; iptables -X
    fi

    # 3. BASELINE
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow Established
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A OUTPUT -p icmp -j ACCEPT

    # 4. ORCHESTRATION WHITELIST
    if [ "$IS_K8S" = true ]; then
        iptables -A INPUT -i cni+ -j ACCEPT; iptables -A OUTPUT -o cni+ -j ACCEPT
        iptables -A INPUT -i flannel+ -j ACCEPT; iptables -A OUTPUT -o flannel+ -j ACCEPT
        iptables -A INPUT -i calico+ -j ACCEPT; iptables -A OUTPUT -o calico+ -j ACCEPT
        iptables -A INPUT -i cilium+ -j ACCEPT; iptables -A OUTPUT -o cilium+ -j ACCEPT
        iptables -A INPUT -i tunl0 -j ACCEPT; iptables -A OUTPUT -o tunl0 -j ACCEPT
    fi
    if [ "$IS_DOCKER" = true ]; then
        iptables -A INPUT -i docker0 -j ACCEPT; iptables -A OUTPUT -o docker0 -j ACCEPT
    fi

    # 5. INBOUND RULES
    IFS=" " read -r -a U_IN_TCP <<< "$(echo "${IN_TCP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    IFS=" " read -r -a U_IN_UDP <<< "$(echo "${IN_UDP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    
    for port in "${U_IN_TCP[@]}"; do [ ! -z "$port" ] && iptables -A INPUT -p tcp --dport $port -m conntrack --ctstate NEW -j ACCEPT; done
    for port in "${U_IN_UDP[@]}"; do [ ! -z "$port" ] && iptables -A INPUT -p udp --dport $port -m conntrack --ctstate NEW -j ACCEPT; done

    # 6. OUTBOUND RULES
    IFS=" " read -r -a U_OUT_TCP <<< "$(echo "${OUT_TCP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    IFS=" " read -r -a U_OUT_UDP <<< "$(echo "${OUT_UDP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

    for port in "${U_OUT_TCP[@]}"; do [ ! -z "$port" ] && iptables -A OUTPUT -p tcp --dport $port -m conntrack --ctstate NEW -j ACCEPT; done
    for port in "${U_OUT_UDP[@]}"; do [ ! -z "$port" ] && iptables -A OUTPUT -p udp --dport $port -m conntrack --ctstate NEW -j ACCEPT; done

    # 7. LOGGING
    iptables -A INPUT -m limit --limit 2/sec -j LOG --log-prefix "FW-DROP-IN: " --log-level 4
    iptables -A OUTPUT -m limit --limit 2/sec -j LOG --log-prefix "FW-DROP-OUT: " --log-level 4

    # 8. DROP POLICY
    iptables -P INPUT DROP
    if [ "$IS_K8S" = false ]; then
        iptables -P OUTPUT DROP
    else
        echo "    > K8s Detected: Defaulting OUTPUT to ACCEPT."
        iptables -P OUTPUT ACCEPT
    fi
    
    if [ "$IS_DOCKER" = false ] && [ "$IS_K8S" = false ]; then
        iptables -P FORWARD DROP
    fi
}

save_persistence() {
    if [ "$PERSIST" = true ]; then
        if command -v dnf &> /dev/null || command -v yum &> /dev/null; then service iptables save
        elif command -v apt-get &> /dev/null; then netfilter-persistent save
        else mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; fi
        echo "    > Rules saved."
    fi
}

# --- RUNTIME ---
check_root
prepare_os
configure_logging

if [ $# -eq 0 ]; then interactive_menu; else parse_args "$@"; fi

detect_orchestration
start_failsafe
apply_rules
confirm_failsafe

if ps -p $FAILSAFE_PID > /dev/null; then
   kill $FAILSAFE_PID 2>/dev/null
   save_persistence
   echo -e "\n[+] FIREWALL SECURED (IN & OUT)."
fi