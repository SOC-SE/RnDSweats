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

# IntProc (Alpine Multi-Interface + Container Fix)
#
#    Supports monitoring multiple interfaces.
#    Fixes "eth0@if..." naming issues in LXC/LXD/Docker containers.
#    Original Design by Samuel Brucker 2025-2026.
#

# Color codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
NC="\e[0m"

# Config and log files
config_file="/etc/IntProc/IntProc.conf"
log_file="/var/log/IntProc.log"
iptables_file="/etc/IntProc/iptables.rules"
routes_file="/etc/IntProc/routes.txt"

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

resolve_dependencies() {
    local packages_to_install=""
    local missing_flag=0

    if ! command -v ip >/dev/null 2>&1; then packages_to_install="$packages_to_install iproute2"; missing_flag=1; fi
    if ! command -v iptables >/dev/null 2>&1; then packages_to_install="$packages_to_install iptables"; missing_flag=1; fi
    # Check for coreutils using apk info to bypass BusyBox masquerade
    if ! apk info -e coreutils >/dev/null 2>&1; then packages_to_install="$packages_to_install coreutils"; missing_flag=1; fi

    if [ $missing_flag -eq 1 ]; then
        echo -e "${YELLOW}Missing dependencies. Installing: $packages_to_install...${NC}"
        apk update >/dev/null 2>&1
        apk add --no-cache $packages_to_install
    fi
}

validate_cidr() {
    local ip_cidr="$1"
    if [[ "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local cidr=${ip_cidr##*/}
        if [ "$cidr" -gt 32 ]; then return 1; fi
        return 0
    else
        return 1
    fi
}

get_available_interfaces() {
    # CONTAINER FIX: 
    # 'sed s/@.*//' removes the @if56 suffix common in LXC/LXD containers
    ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | tr '\n' ' '
}

get_current_ip() {
    local iface="$1"
    # Safely get IP even if multiple exist, grab the first primary one
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

    # Only calculate masks if we are actually dealing with an IP change
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

    # Gateway is system-wide
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

backup_iptables() {
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$iptables_file" || return 1
        echo -e "${GREEN}iptables rules backed up.${NC}"
    fi
}

backup_routes() {
    ip route show > "$routes_file" || return 1
    echo -e "${GREEN}Route table backed up.${NC}"
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

check_root
resolve_dependencies

# --- INSTALLATION MODE ---
if [ "$1" = "--install" ]; then
    echo -e "${YELLOW}Starting Multi-Interface Installation...${NC}"
    mkdir -p /etc/IntProc
    
    # Init config file
    > "$config_file"

    echo -e "${YELLOW}Detecting available network interfaces...${NC}"
    available_ifaces=$(get_available_interfaces)
    interfaces=($available_ifaces) # Convert to array
    
    selected_interfaces=""
    
    echo "Available interfaces:"
    for i in "${!interfaces[@]}"; do
        echo "$((i+1)). ${interfaces[i]}"
    done
    
    echo -e "${YELLOW}Enter the numbers of the interfaces to protect, separated by space (e.g. '1 2'):${NC}"
    read -p "> " selection
    
    # Process selection
    for num in $selection; do
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#interfaces[@]}" ]; then
            iface_name="${interfaces[$((num-1))]}"
            selected_interfaces="$selected_interfaces $iface_name"
            
            # Get IP for this specific interface
            current_ip=$(get_current_ip "$iface_name")
            while true; do
                read -p "Enter static IP/CIDR for $iface_name [$current_ip]: " input_ip
                final_ip=${input_ip:-$current_ip}
                if validate_cidr "$final_ip"; then
                    # Write dynamically named variable to config (e.g., IP_eth0="...")
                    echo "IP_$iface_name=\"$final_ip\"" >> "$config_file"
                    break
                else
                    echo -e "${RED}Invalid IP format.${NC}"
                fi
            done
        fi
    done
    
    # Save the list of monitored interfaces
    echo "INTERFACES=\"$selected_interfaces\"" >> "$config_file"
    
    # Global settings (Gateway and DNS are usually system-wide)
    current_gw=$(get_current_gateway)
    read -p "Enter default system gateway [$current_gw]: " gw
    gw=${gw:-$current_gw}
    echo "GATEWAY=\"$gw\"" >> "$config_file"

    current_dns=$(get_current_dns "any")
    read -p "Enter DNS servers [$current_dns]: " dns
    dns=${dns:-$current_dns}
    echo "DNS=\"$dns\"" >> "$config_file"
    
    echo "IPTABLES_FILE=\"$iptables_file\"" >> "$config_file"
    echo "ROUTES_FILE=\"$routes_file\"" >> "$config_file"

    read -p "Backup iptables? (y/n) [y]: " backup_ipt
    [ "${backup_ipt:-y}" = "y" ] && backup_iptables

    read -p "Backup routes? (y/n) [y]: " backup_rts
    [ "${backup_rts:-y}" = "y" ] && backup_routes

    echo -e "${GREEN}Configuration saved.${NC}"

    # Create OpenRC Service
    cat <<EOF > /etc/init.d/intproc
#!/sbin/openrc-run

name="IntProc"
description="Network Interface Protector"
command="/bin/bash"
command_args="/usr/local/bin/IntProc.sh"
command_background=true
pidfile="/run/intproc.pid"

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/intproc
    cp "$0" /usr/local/bin/IntProc.sh
    chmod +x /usr/local/bin/IntProc.sh
    
    rc-update add intproc default
    rc-service intproc restart
    echo -e "${GREEN}Service installed and started.${NC}"
    exit 0
fi

# --- MONITORING MODE ---
if [ ! -f "$config_file" ]; then
    echo "Error: Configuration file not found."
    exit 1
fi
source "$config_file"

touch "$log_file"
chmod 644 "$log_file"

while true; do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 1. GLOBAL CHECKS (Gateway, DNS, Firewall)
    
    # Check Gateway
    current_gw=$(get_current_gateway)
    log_gw="${current_gw:-none}"
    if [ "$current_gw" != "$GATEWAY" ]; then
        echo "[$timestamp] Global Gateway changed ($GATEWAY -> $log_gw). Reverting." >> "$log_file"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "gateway"
    fi

    # Check DNS
    current_dns=$(get_current_dns "any")
    flat_current_dns=$(echo "$current_dns" | xargs)
    flat_target_dns=$(echo "$DNS" | xargs)
    if [ "$flat_current_dns" != "$flat_target_dns" ]; then
        echo "[$timestamp] DNS changed ($flat_target_dns -> $flat_current_dns). Reverting." >> "$log_file"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "dns"
    fi

    # Check iptables
    if [ -f "$IPTABLES_FILE" ] && command -v iptables-save >/dev/null 2>&1; then
        current_ipt=$(iptables-save)
        saved_ipt=$(cat "$IPTABLES_FILE")
        if [ "$current_ipt" != "$saved_ipt" ]; then
            echo "[$timestamp] iptables changed. Reverting." >> "$log_file"
            iptables-restore < "$IPTABLES_FILE"
        fi
    fi
    
    # Check Route Table
    if [ -f "$ROUTES_FILE" ] && command -v ip >/dev/null 2>&1; then
        current_routes=$(ip route show | sort)
        saved_routes=$(sort "$ROUTES_FILE")
        if [ "$current_routes" != "$saved_routes" ]; then
            echo "[$timestamp] Route table changed. Reverting." >> "$log_file"
            ip route flush table main
            while IFS= read -r line; do
                [ -n "$line" ] && ip route add $line 2>> "$log_file"
            done < "$ROUTES_FILE"
        fi
    fi

    # 2. PER-INTERFACE CHECKS (IP Addresses)
    # Loop through the list of interfaces saved in config
    for iface in $INTERFACES; do
        # Dynamically construct variable name (e.g., IP_eth0)
        target_ip_var="IP_$iface"
        # Indirect reference to get the value
        target_ip="${!target_ip_var}"

        if ! ip link show "$iface" up >/dev/null 2>&1; then
            echo "[$timestamp] Interface $iface is down. Bringing up." >> "$log_file"
            ip link set "$iface" up 2>> "$log_file"
        fi
        
        current_ip=$(get_current_ip "$iface")
        
        if [ "$current_ip" != "$target_ip" ]; then
            echo "[$timestamp] IP on $iface changed ($target_ip -> $current_ip). Reverting." >> "$log_file"
            # Pass the specific IP for this interface
            revert_settings "$iface" "$target_ip" "$GATEWAY" "$DNS" "ip"
        fi
    done

    sleep 5
done