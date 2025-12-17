#!/bin/sh
# This shell header ensures the script runs even if Bash is missing on Alpine.
# It checks for Bash, installs it if missing, and then re-executes itself.

if [ -z "$BASH_VERSION" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        echo "Bash not found. Attempting to install bash..."
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Need root to install bash. Please run with sudo."
            exit 1
        fi
        
        apk update && apk add bash || {
            echo "CRITICAL ERROR: Failed to install Bash."
            echo "Please check your internet connection and repositories."
            exit 1
        }
    fi
    # Re-execute the script using bash
    exec bash "$0" "$@"
fi

# ==============================================================================
#  BELOW THIS LINE IS THE BASH SCRIPT
# ==============================================================================

# intproc (Alpine Final Edition v4 - Toggle Update)
#
#    A self-healing network defense system for Alpine Linux.
#    Features: Multi-interface, Smart Toggle (Auto-Save), Interactive Backup.
#    Original Design by Samuel Brucker 2025-2026.
#

# Color codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
NC="\e[0m"

# Config and log files
config_file="/etc/IntProc/IntProc.conf"
log_file="/var/log/IntProc.log"
iptables_file="/etc/IntProc/iptables.rules"
routes_file="/etc/IntProc/routes.txt"
maintenance_file="/etc/IntProc/maintenance.lock"

# --- HELPER FUNCTIONS ---

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

show_help() {
    echo -e "${CYAN}intproc - Network Interface Protector (Alpine Edition)${NC}"
    echo "Usage: intproc [OPTION]"
    echo ""
    echo "Options:"
    echo -e "  ${GREEN}--install${NC}   Install the service and configure initial settings."
    echo -e "  ${GREEN}--toggle${NC}    Switch between Maintenance Mode (Pause) and Protection (Resume)."
    echo -e "               - If Pausing: Simply stops protection so you can make changes."
    echo -e "               - If Resuming: AUTOMATICALLY SAVES current state as the new baseline."
    echo -e "  ${GREEN}-h, --help${NC}  Show this help message."
    echo ""
    exit 0
}

resolve_dependencies() {
    local packages_to_install=""
    local missing_flag=0

    if ! command -v ip >/dev/null 2>&1; then packages_to_install="$packages_to_install iproute2"; missing_flag=1; fi
    if ! command -v iptables >/dev/null 2>&1; then packages_to_install="$packages_to_install iptables"; missing_flag=1; fi
    if ! apk info -e coreutils >/dev/null 2>&1; then packages_to_install="$packages_to_install coreutils"; missing_flag=1; fi

    if [ $missing_flag -eq 1 ]; then
        echo -e "${YELLOW}Missing dependencies. Installing: $packages_to_install...${NC}"
        apk update >/dev/null 2>&1
        apk add --no-cache $packages_to_install
    fi
}

get_available_interfaces() {
    # Removes @if... suffix for containers
    ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | tr '\n' ' '
}

get_current_ip() {
    local iface="$1"
    ip -4 addr show dev "$iface" | awk '/inet / {print $2}' | head -n 1
}

get_current_gateway() {
    ip route show default | awk '/default/ {print $3}' | head -1
}

get_current_dns() {
    grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ' | xargs
}

cidr_to_netmask() {
    local cidr="$1"
    local mask=0xffffffff
    mask=$((mask << (32 - cidr)))
    printf "%d.%d.%d.%d\n" $((mask >> 24 & 255)) $((mask >> 16 & 255)) $((mask >> 8 & 255)) $((mask & 255))
}

revert_settings() {
    local iface="$1"
    local target_ip_cidr="$2"
    local target_gw="$3"
    local target_dns="$4"
    local change_type="$5"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    if [ "$change_type" = "ip" ]; then
        local target_ip="${target_ip_cidr%%/*}"
        local target_cidr="${target_ip_cidr##*/}"
        local target_mask=$(cidr_to_netmask "$target_cidr")
        
        if command -v ip >/dev/null 2>&1; then
            echo "Using ip command to revert IP on $iface..."
            ip addr flush dev "$iface"
            ip addr add "$target_ip_cidr" dev "$iface"
            ip link set "$iface" up
        elif command -v ifconfig >/dev/null 2>&1; then
            ifconfig "$iface" "$target_ip" netmask "$target_mask" up
        fi
    fi

    if [ "$change_type" = "gateway" ]; then
        echo "Using ip command to revert Gateway..."
        ip route del default 2>/dev/null
        ip route add default via "$target_gw"
    fi

    if [ "$change_type" = "dns" ]; then
        echo "[$timestamp] Reverting DNS in /etc/resolv.conf..." >> "$log_file"
        > /etc/resolv.conf
        IFS=' ' read -r -a dns_array <<< "$target_dns"
        for dns in "${dns_array[@]}"; do
            echo "nameserver $dns" >> /etc/resolv.conf
        done
    fi
    return 0
}

snapshot_config() {
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}Error: No config file found. Run --install first.${NC}"
        exit 1
    fi
    
    # Load old config to get the list of interfaces to check
    source "$config_file"
    echo -e "${CYAN}Snapshotting current system state to configuration...${NC}"
    
    current_gw=$(get_current_gateway)
    current_dns=$(get_current_dns "any")
    temp_config="/tmp/IntProc_new.conf"
    
    # Reconstruct the config file with CURRENT system values
    echo "INTERFACES=\"$INTERFACES\"" > "$temp_config"
    echo "GATEWAY=\"$current_gw\"" >> "$temp_config"
    echo "DNS=\"$current_dns\"" >> "$temp_config"
    echo "IPTABLES_FILE=\"$iptables_file\"" >> "$temp_config"
    echo "ROUTES_FILE=\"$routes_file\"" >> "$temp_config"
    
    for iface in $INTERFACES; do
        current_ip=$(get_current_ip "$iface")
        echo "IP_$iface=\"$current_ip\"" >> "$temp_config"
        echo "  - Updated IP for $iface: $current_ip"
    done
    
    mv "$temp_config" "$config_file"
    
    # Check if backup files exist (meaning user opted in) before updating them
    if [ -f "$iptables_file" ]; then
        iptables-save > "$iptables_file"
        echo "  - Updated iptables backup."
    fi
    
    if [ -f "$routes_file" ]; then
        ip route show > "$routes_file"
        echo "  - Updated routes backup."
    fi
    
    echo -e "${GREEN}New configuration saved!${NC}"
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

# Check for help before root check (users should be able to see help without sudo)
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
fi

check_root
resolve_dependencies

# --- COMMAND LINE ARGUMENTS ---

# 1. Toggle Mode (Smart Pause/Resume)
if [ "$1" = "--toggle" ]; then
    if [ -f "$maintenance_file" ]; then
        # --- RESUME LOGIC (With Auto-Save) ---
        echo -e "${CYAN}Maintenance Mode is currently ACTIVE.${NC}"
        echo "Reading current network state to update baseline..."
        
        snapshot_config
        
        rm "$maintenance_file"
        echo -e "${GREEN}Protection RESUMED.${NC}"
        echo "The daemon will now defend the NEW configuration."
    else
        # --- PAUSE LOGIC ---
        touch "$maintenance_file"
        echo -e "${YELLOW}Maintenance Mode ACTIVATED.${NC}"
        echo "Protection is PAUSED. You may now make changes to IPs, routes, or firewall."
        echo "Run 'intproc --toggle' again to Save & Resume."
    fi
    exit 0
fi

# 2. INSTALLATION MODE
if [ "$1" = "--install" ]; then
    echo -e "${YELLOW}Starting intproc Installation...${NC}"
    mkdir -p /etc/IntProc
    > "$config_file"
    
    available_ifaces=$(get_available_interfaces)
    interfaces=($available_ifaces)
    
    echo "Available interfaces:"
    for i in "${!interfaces[@]}"; do
        echo "$((i+1)). ${interfaces[i]}"
    done
    
    read -p "Enter numbers of interfaces to protect (e.g. '1 2'): " selection
    selected_interfaces=""
    
    for num in $selection; do
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#interfaces[@]}" ]; then
            iface_name="${interfaces[$((num-1))]}"
            selected_interfaces="$selected_interfaces $iface_name"
            
            current_ip=$(get_current_ip "$iface_name")
            read -p "Enter IP/CIDR for $iface_name [$current_ip]: " final_ip
            final_ip=${final_ip:-$current_ip}
            echo "IP_$iface_name=\"$final_ip\"" >> "$config_file"
        fi
    done
    
    echo "INTERFACES=\"$selected_interfaces\"" >> "$config_file"
    
    current_gw=$(get_current_gateway)
    read -p "Enter Gateway [$current_gw]: " gw
    echo "GATEWAY=\"${gw:-$current_gw}\"" >> "$config_file"

    current_dns=$(get_current_dns "any")
    read -p "Enter DNS [$current_dns]: " dns
    echo "DNS=\"${dns:-$current_dns}\"" >> "$config_file"
    
    echo "IPTABLES_FILE=\"$iptables_file\"" >> "$config_file"
    echo "ROUTES_FILE=\"$routes_file\"" >> "$config_file"

    # --- RESTORED PROMPTS ---
    read -p "Backup current iptables rules? (y/n) [y]: " backup_ipt
    backup_ipt=${backup_ipt:-y}
    if [ "$backup_ipt" = "y" ]; then
        iptables-save > "$iptables_file"
        echo -e "${GREEN}iptables rules backed up.${NC}"
    else
        echo -e "${YELLOW}Skipping iptables backup.${NC}"
        rm -f "$iptables_file"
    fi

    read -p "Backup current route table? (y/n) [y]: " backup_rts
    backup_rts=${backup_rts:-y}
    if [ "$backup_rts" = "y" ]; then
        ip route show > "$routes_file"
        echo -e "${GREEN}Route table backed up.${NC}"
    else
        echo -e "${YELLOW}Skipping route table backup.${NC}"
        rm -f "$routes_file"
    fi
    # ------------------------

    echo -e "${GREEN}Configuration saved.${NC}"

    cat <<EOF > /etc/init.d/intproc
#!/sbin/openrc-run
name="intproc"
description="Network Interface Protector"
command="/bin/bash"
command_args="/usr/local/bin/intproc"
command_background=true
pidfile="/run/intproc.pid"
depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/intproc
    cp "$0" /usr/local/bin/intproc
    chmod +x /usr/local/bin/intproc
    rc-update add intproc default
    rc-service intproc restart
    echo -e "${GREEN}Service installed and started.${NC}"
    exit 0
fi

# --- MONITORING MODE (Daemon) ---

if [ ! -f "$config_file" ]; then
    echo -e "${RED}Error: Configuration not found.${NC}"
    echo -e "Please run: ${GREEN}./intProcAlpineEdition.sh --help${NC} for usage instructions."
    exit 1
fi

source "$config_file"
touch "$log_file"
chmod 644 "$log_file"

while true; do
    if [ -f "$maintenance_file" ]; then
        sleep 5
        continue
    fi

    # CRITICAL UPDATE: Reload config in case it was changed via toggle/snapshot
    # This ensures the daemon is always defending the LATEST saved state.
    if [ -f "$config_file" ]; then
        source "$config_file"
    fi

    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 1. Global Checks
    current_gw=$(get_current_gateway)
    if [ "$current_gw" != "$GATEWAY" ]; then
        echo "[$timestamp] Gateway changed. Reverting." >> "$log_file"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "gateway"
    fi

    current_dns=$(get_current_dns "any")
    flat_current_dns=$(echo "$current_dns" | xargs)
    flat_target_dns=$(echo "$DNS" | xargs)
    if [ "$flat_current_dns" != "$flat_target_dns" ]; then
        echo "[$timestamp] DNS changed. Reverting." >> "$log_file"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "dns"
    fi

    if [ -f "$IPTABLES_FILE" ] && command -v iptables-save >/dev/null 2>&1; then
        current_ipt=$(iptables-save)
        saved_ipt=$(cat "$IPTABLES_FILE")
        if [ "$current_ipt" != "$saved_ipt" ]; then
            echo "[$timestamp] iptables changed. Reverting." >> "$log_file"
            iptables-restore < "$IPTABLES_FILE"
        fi
    fi
    
    if [ -f "$ROUTES_FILE" ] && command -v ip >/dev/null 2>&1; then
        current_routes=$(ip route show | sort)
        saved_routes=$(sort "$ROUTES_FILE")
        if [ "$current_routes" != "$saved_routes" ]; then
            echo "[$timestamp] Routes changed. Reverting." >> "$log_file"
            ip route flush table main
            while IFS= read -r line; do
                [ -n "$line" ] && ip route add $line 2>> "$log_file"
            done < "$ROUTES_FILE"
        fi
    fi

    # 2. Per-Interface Checks
    for iface in $INTERFACES; do
        target_ip_var="IP_$iface"
        target_ip="${!target_ip_var}"

        if ! ip link show "$iface" up >/dev/null 2>&1; then
            ip link set "$iface" up 2>> "$log_file"
        fi
        
        current_ip=$(get_current_ip "$iface")
        
        if [ "$current_ip" != "$target_ip" ]; then
            echo "[$timestamp] IP on $iface changed. Reverting." >> "$log_file"
            revert_settings "$iface" "$target_ip" "$GATEWAY" "$DNS" "ip"
        fi
    done

    sleep 5
done