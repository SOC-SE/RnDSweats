#!/bin/bash
# =============================================================================
# UNIVERSAL SENTINEL FIREWALL
# Logic: Category Drill-Down | Strict In/Out | Anti-C2 | Failsafe
# Supported: Debian/RHEL/Gentoo/Alpine (Systemd & OpenRC)
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
PERSIST=false

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

# Wrapper to handle Systemd vs OpenRC differences
manage_service() {
    local service=$1
    local action=$2 # start, stop, restart, enable, disable, mask, is-active

    # 1. Systemd
    if command -v systemctl &> /dev/null && [ -d /run/systemd/system ]; then
        case $action in
            is-active) systemctl is-active --quiet "$service" ;;
            enable)    systemctl enable "$service" --now ;;
            disable)   systemctl disable "$service" --now ;;
            mask)      systemctl mask "$service" ;;
            *)         systemctl "$action" "$service" ;;
        esac

    # 2. OpenRC
    elif command -v rc-service &> /dev/null; then
        case $action in
            is-active) rc-service "$service" status 2>/dev/null | grep -q "started" ;;
            enable)    rc-update add "$service" default && rc-service "$service" start ;;
            disable)   rc-service "$service" stop && rc-update delete "$service" default ;;
            mask)      echo "    ! OpenRC does not support 'mask', stopping/disabling only." && rc-service "$service" stop ;;
            *)         rc-service "$service" "$action" ;;
        esac
    fi
}

# --- DETECTION & PREP ---
prepare_os() {
    echo "[*] Detecting Package Manager..."
    
    # 1. GENTOO (Portage)
    if command -v emerge &> /dev/null; then
        echo "    > Gentoo detected. Checking IPTables..."
        emerge --noreplace net-firewall/iptables
        manage_service iptables enable

    # 2. RHEL/CentOS/Fedora (DNF/YUM)
    elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        # Disable Firewalld if active
        if manage_service firewalld is-active; then
            manage_service firewalld stop
            manage_service firewalld disable
            manage_service firewalld mask
        fi
        # Use dnf if available, fall back to yum
        if command -v dnf &> /dev/null; then
            rpm -q iptables-services &> /dev/null || dnf install -y iptables-services
        else
            rpm -q iptables-services &> /dev/null || yum install -y iptables-services
        fi
        manage_service iptables enable

    # 3. Debian/Ubuntu (APT)
    elif command -v apt-get &> /dev/null; then
        dpkg -s iptables-persistent &> /dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
    
    # 4. Alpine (APK)
    elif command -v apk &> /dev/null; then
        apk add iptables
        manage_service iptables enable
    fi
}

configure_logging() {
    if [ ! -d "$LOG_DIR" ]; then mkdir -p "$LOG_DIR"; fi
    
    # Configure rsyslog if present
    if [ -d "/etc/rsyslog.d" ] && command -v rsyslogd &> /dev/null; then
        echo ':msg, contains, "FW-DROP" -'"$LOG_FILE" > /etc/rsyslog.d/99-defensive-firewall.conf
        echo '& stop' >> /etc/rsyslog.d/99-defensive-firewall.conf
        manage_service rsyslog restart
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
    echo "=== UNIVERSAL FIREWALL GENERATOR (Multi-Init Supported) =="
    
    # 1. ESSENTIALS
    echo "--- ESSENTIALS ---"
    read -r -p "1. Allow SSH (Inbound 22)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || IN_TCP+=("22") # Default Yes

    read -r -p "2. Allow DNS Lookup (Outbound 53)? [Y/n]: " ans
    [[ "$ans" =~ ^[Nn]$ ]] || { OUT_UDP+=("53"); OUT_TCP+=("53"); }

    read -r -p "3. Allow System Updates (Outbound 80/443)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_TCP+=("80" "443")

    read -r -p "4. Allow NTP Sync (Outbound 123)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && OUT_UDP+=("123")

    # 2. STANDARD SERVICES
    echo -e "\n--- STANDARD SERVICES ---"
    read -r -p "5. Configure Web/Mail/File Services? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        read -r -p "   > Web Server (In: 80/443)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("80" "443")
        read -r -p "   > Mail Server (In: SMTP/IMAP/POP3)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("25" "465" "587" "110" "143" "993" "995")
        read -r -p "   > SMB/Windows Share (In: 139/445)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("139" "445")
        read -r -p "   > FTP Server (In: 20/21)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("20" "21"); MOD_FTP=true; }
        read -r -p "   > NFS Share (In: 2049)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("2049"); IN_UDP+=("2049"); }
    fi

    # 3. INFRASTRUCTURE
    echo -e "\n--- INFRASTRUCTURE ---"
    read -r -p "6. Configure DNS/Auth/Databases? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        read -r -p "   > DNS Server (In: 53)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("53"); IN_UDP+=("53"); }
        read -r -p "   > LDAP (In: 389/636)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("389" "636")
        read -r -p "   > Kerberos (In: 88)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("88"); IN_UDP+=("88"); }
        read -r -p "   > MySQL/MariaDB (In: 3306)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("3306")
        read -r -p "   > PostgreSQL (In: 5432)? [y/N]: " sub; [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("5432")
    fi

    # 4. SECURITY TOOLS
    echo -e "\n--- SECURITY TOOLS (Server = Inbound / Agent = Outbound) ---"
    read -r -p "7. Configure Splunk/Wazuh/ELK/Salt? [y/N]: " cat_ans
    if [[ "$cat_ans" =~ ^[Yy]$ ]]; then
        # SPLUNK
        read -r -p "   > Splunk SERVER (In: 8000/8089/9997/514)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("8000" "8089" "9997" "514"); IN_UDP+=("514"); }
        read -r -p "   > Splunk FORWARDER (Out: 9997/8089)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("9997" "8089")

        # WAZUH
        read -r -p "   > Wazuh SERVER (In: 1514/1515/55000)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("1514" "1515" "55000" "443")
        read -r -p "   > Wazuh AGENT (Out: 1514/1515)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("1514" "1515")

        # ELK
        read -r -p "   > ELK Stack (In: 9200/9300/5601/514)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && { IN_TCP+=("9200" "9300" "5601" "5044" "514"); IN_UDP+=("514"); }
        read -r -p "   > Elastic AGENT (Out: 8220/9200)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("8220" "9200")
        
        # SALT
        read -r -p "   > Salt MASTER (In: 4505-4506, 8881, 3000)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("4505" "4506" "8881" "3000")
        read -r -p "   > Salt MINION (Out: 4505/4506)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("4505" "4506")

        # VELOCIRAPTOR
        read -r -p "   > Velociraptor SERVER (In: 8000-8003)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("8000" "8001" "8003")
        read -r -p "   > Velociraptor AGENT (Out: 8001)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && OUT_TCP+=("8001")
        
        # PALO ALTO
        read -r -p "   > Palo Alto Mgmt (In: 443/22)? [y/N]: " sub
        [[ "$sub" =~ ^[Yy]$ ]] && IN_TCP+=("443" "22")
    fi

    # 5. ORCHESTRATION & MISC
    echo -e "\n--- MISC ---"
    read -r -p "8. Minecraft Server (In: 25565)? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && { IN_TCP+=("25565"); IN_UDP+=("25565"); }
    
    read -r -p "9. Kubernetes Node (Force Enable)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        IS_K8S=true
        IN_TCP+=("6443" "10250")
        echo "    (K8s Safe-Flush & CNI Whitelist Enabled)"
    fi

    echo -e "\n--- FINALIZE ---"
    read -r -p "10. Enable Persistence? [Y/n]: " ans
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
            --custom-in )
                shift
                IFS=',' read -ra ADDR <<< "$1"
                for i in "${ADDR[@]}"; do
                    if [[ "$i" =~ ^[0-9]+$ ]] && [ "$i" -ge 1 ] && [ "$i" -le 65535 ]; then
                        IN_TCP+=("$i")
                    else
                        echo "    [!] Invalid port ignored: $i" >&2
                    fi
                done
                ;;
            --custom-out )
                shift
                IFS=',' read -ra ADDR <<< "$1"
                for i in "${ADDR[@]}"; do
                    if [[ "$i" =~ ^[0-9]+$ ]] && [ "$i" -ge 1 ] && [ "$i" -le 65535 ]; then
                        OUT_TCP+=("$i")
                    else
                        echo "    [!] Invalid port ignored: $i" >&2
                    fi
                done
                ;;
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
    read -r -t $FAILSAFE_DELAY -p "Apply Permanent? (y/N): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        kill $FAILSAFE_PID 2>/dev/null
        echo -e "[+] Configuration Confirmed."
    else
        echo -e "[!] Reverting..."
    fi
}

apply_rules() {
    echo "[*] Applying Rules..."

    # Backup current rules before making changes
    local backup_dir="/var/backups/iptables"
    mkdir -p "$backup_dir"
    local backup_file
    backup_file="$backup_dir/rules.pre-ccdc.$(date +%Y%m%d_%H%M%S)"
    if iptables-save > "$backup_file" 2>/dev/null; then
        echo "    > Backed up current rules to: $backup_file"
    else
        echo "    > Warning: Could not backup current rules"
    fi

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
    
    for port in "${U_IN_TCP[@]}"; do [[ -n "$port" ]] && iptables -A INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT; done
    for port in "${U_IN_UDP[@]}"; do [[ -n "$port" ]] && iptables -A INPUT -p udp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT; done

    # 6. OUTBOUND RULES
    IFS=" " read -r -a U_OUT_TCP <<< "$(echo "${OUT_TCP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    IFS=" " read -r -a U_OUT_UDP <<< "$(echo "${OUT_UDP[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"

    for port in "${U_OUT_TCP[@]}"; do [[ -n "$port" ]] && iptables -A OUTPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT; done
    for port in "${U_OUT_UDP[@]}"; do [[ -n "$port" ]] && iptables -A OUTPUT -p udp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT; done

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
        echo "    > Saving rules..."
        
        # 1. RHEL/CentOS
        if command -v dnf &> /dev/null || command -v yum &> /dev/null; then 
            service iptables save
            
        # 2. Debian/Ubuntu (netfilter-persistent)
        elif command -v apt-get &> /dev/null; then 
            netfilter-persistent save
            
        # 3. Gentoo/Alpine (OpenRC)
        elif command -v rc-service &> /dev/null; then
            # The standard OpenRC save
            /etc/init.d/iptables save || rc-service iptables save
            
        # 4. Fallback
        else 
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        fi
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