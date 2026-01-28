#!/bin/bash
# =============================================================================
# UNIVERSAL SENTINEL FIREWALL 
# Logic: Category Drill-Down | Strict In/Out | Anti-C2 | Failsafe
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
    echo "This script uses an interactive menu to strictly open ports."
    echo "Use --help to see this message. Run without arguments for the menu."
    echo "Run with specific flags to bypass menu (e.g., --ssh --splunk-fwd)."
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
    echo "=== UNIVERSAL FIREWALL GENERATOR =="
    
    # 1. ESSENTIALS (Top Level - High Priority)
    echo "--- ESSENTIALS ---"
    read -p "1. Allow SSH (Inbound 22)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || IN_TCP+=("22") # Default Yes

    read -p "2. Allow DNS Lookup (Outbound 53)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || { OUT_UDP+=("53"); OUT_TCP+=("53"); }

    read -p "3. Allow System Updates (Outbound 80/443)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_TCP+=("80" "443")

    read -p "4. Allow NTP Sync (Outbound 123)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_UDP+=("123")

    # 2. STANDARD SERVICES (Category Drill-Down)
    echo -e "\n--- STANDARD SERVICES ---"
    read -p "5. Configure Web/Mail/File Services? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        read -p "   > Web Server (In: 80/443)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("80" "443")
        read -p "   > Mail Server (In: SMTP/IMAP/POP3)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("25" "465" "587" "110" "143" "993" "995")
        read -p "   > SMB/Windows Share (In: 139/445)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("139" "445")
        read -p "   > FTP Server (In: 20/21)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("20" "21"); MOD_FTP=true; }
        read -p "   > NFS Share (In: 2049)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("2049"); IN_UDP+=("2049"); }
    fi

    # 3. INFRASTRUCTURE (Category Drill-Down)
    echo -e "\n--- INFRASTRUCTURE ---"
    read -p "6. Configure DNS/Auth/Databases? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        read -p "   > DNS Server (In: 53)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("53"); IN_UDP+=("53"); }
        read -p "   > LDAP (In: 389/636)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("389" "636")
        read -p "   > Kerberos (In: 88)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("88"); IN_UDP+=("88"); }
        read -p "   > MySQL/MariaDB (In: 3306)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("3306")
        read -p "   > PostgreSQL (In: 5432)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("5432")
    fi

    # 4. SECURITY TOOLS (Category Drill-Down)
    echo -e "\n--- SECURITY TOOLS (Server = Inbound / Agent = Outbound) ---"
    read -p "7. Configure Splunk/Wazuh/ELK/Salt? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        # SPLUNK
        read -p "   > Splunk SERVER (In: 8000/8089/9997/514)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("8000" "8089" "9997" "514"); IN_UDP+=("514"); }
        read -p "   > Splunk FORWARDER (Out: 9997/8089)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("9997" "8089")

        # WAZUH
        read -p "   > Wazuh SERVER (In: 1514/1515/55000)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("1514" "1515" "55000" "443")
        read -p "   > Wazuh AGENT (Out: 1514/1515)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("1514" "1515")

        # ELK
        read -p "   > ELK Stack (In: 9200/9300/5601/514)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("9200" "9300" "5601" "5044" "514"); IN_UDP+=("514"); }
        read -p "   > Elastic AGENT (Out: 8220/9200)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("8220" "9200")
        
        # SALT
        read -p "   > Salt MASTER (In: 4505-4506, 8881, 3000)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("4505" "4506" "8881" "3000")
        read -p "   > Salt MINION (Out: 4505/4506)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("4505" "4506")

        # VELOCIRAPTOR
        read -p "   > Velociraptor SERVER (In: 8000-8003)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("8000" "8001" "8003")
        read -p "   > Velociraptor AGENT (Out: 8001)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("8001")
        
        # PALO ALTO
        read -p "   > Palo Alto Mgmt (In: 443/22)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("443" "22")
    fi

    # 5. ORCHESTRATION & MISC
    echo -e "\n--- MISC ---"
    read -p "8. Minecraft Server (In: 25565)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("25565"); IN_UDP+=("25565"); }
    
    read -p "9. Kubernetes Node (Force Enable)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        IS_K8S=true
        IN_TCP+=("6443" "10250")
        echo "    (K8s Safe-Flush & CNI Whitelist Enabled)"
    fi

    echo -e "\n--- FINALIZE ---"
    read -p "10. Enable Persistence? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || PERSIST=true
}

parse_args() {
    # Argument parsing
    while [ "$1" != "" ]; do
        case $1 in
            -h | --help )       usage ;;
            --ssh )             IN_TCP+=("22") ;;
            --updates )         OUT_TCP+=("80" "443") ;;
            --dns-resolver )    OUT_UDP+=("53"); OUT_TCP+=("53") ;;
            --ntp-client )      OUT_UDP+=("123") ;;
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
            # Updated Security Blocks
            --splunk-srv )      IN_TCP+=("8000" "8089" "9997" "514"); IN_UDP+=("514") ;;
            --splunk-fwd )      OUT_TCP+=("9997" "8089") ;;
            --wazuh-srv )       IN_TCP+=("1514" "1515" "55000" "443") ;;
            --wazuh-agt )       OUT_TCP+=("1514" "1515") ;;
            --elk )             IN_TCP+=("9200" "9300" "5601" "5044" "514"); IN_UDP+=("514") ;;
            --elk-agt )         OUT_TCP+=("8220" "9200") ;; 
            --velo-srv )        IN_TCP+=("8000" "8001" "8003") ;;
            --velo-agt )        OUT_TCP+=("8001") ;;
            --salt-master )     IN_TCP+=("4505" "4506" "8881" "3000" "8001") ;;
            --salt-minion )     OUT_TCP+=("4505" "4506") ;;
            --palo )            IN_TCP+=("443" "22") ;;
            --minecraft )       IN_TCP+=("25565"); IN_UDP+=("25565") ;;
            --k8s )             IS_K8S=true; IN_TCP+=("6443" "10250") ;;
            --persist )         PERSIST=true ;;
            --custom-in )       shift; IFS=',' read -ra ADDR <<< "$1"; for i in "${ADDR[@]}"; do IN_TCP+=("$i"); done ;;
            --custom-out )      shift; IFS=',' read -ra ADDR <<< "$1"; for i in "${ADDR[@]}"; do OUT_TCP+=("$i"); done ;;
        esac
        shift
    done
}

# --- FAILSAFE & FIREWALL EXECUTION ---
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

apply_rules() {
    echo "[*] Applying Rules..."
    
    if [ "$MOD_FTP" = true ]; then 
        modprobe nf_conntrack_ftp 2>/dev/null || echo "    > Warning: Could not load FTP conntrack."
    fi

    # 1. ACCEPT POLICY (Safety)
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
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A OUTPUT -p icmp -j ACCEPT

    # 3b. ANTI-RECONNAISSANCE - Bad TCP Flag Combinations
    # Drop packets with invalid flag combinations (used for OS fingerprinting/scanning)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                    # NULL scan
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                     # XMAS scan
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP            # XMAS variant
    iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP    # Invalid combo
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP            # SYN+RST
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP            # SYN+FIN
    iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP            # FIN+RST

    # Drop fragmented packets (often used to bypass firewalls)
    iptables -A INPUT -f -j LOG --log-prefix "FW-FRAG: " --log-level 4
    iptables -A INPUT -f -j DROP

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