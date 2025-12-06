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
        
        # FIX 2: Added error handling for network/repo failures
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

# IntProc (Alpine Edition) - Self-Healing Network Interface Protector
#
#    Adapted for Alpine Linux/OpenRC with Auto-Dependency Resolution.
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

# Check root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

# Auto-detect and install dependencies
resolve_dependencies() {
    local packages_to_install=""
    local missing_flag=0

    # 1. Check for IP command (provided by iproute2)
    if ! command -v ip >/dev/null 2>&1; then
        packages_to_install="$packages_to_install iproute2"
        missing_flag=1
    fi

    # 2. Check for iptables
    if ! command -v iptables >/dev/null 2>&1; then
        packages_to_install="$packages_to_install iptables"
        missing_flag=1
    fi

    # 3. Check for GNU coreutils (FIX 1: BusyBox Masquerade)
    # BusyBox provides a limited 'timeout', so command -v checks return true even if full coreutils is missing.
    # We explicitly ask apk if the coreutils package is installed.
    if ! apk info -e coreutils >/dev/null 2>&1; then
         packages_to_install="$packages_to_install coreutils"
         missing_flag=1
    fi

    if [ $missing_flag -eq 1 ]; then
        echo -e "${YELLOW}Missing system dependencies detected.${NC}"
        echo -e "${YELLOW}Installing: $packages_to_install...${NC}"
        
        apk update >/dev/null 2>&1
        apk add --no-cache $packages_to_install
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Dependencies installed successfully.${NC}"
        else
            echo -e "${RED}Error installing dependencies. Please check network/repos.${NC}"
            exit 1
        fi
    fi
}

# FIX 3: Input Validation Helper
validate_cidr() {
    local ip_cidr="$1"
    # Regex checks for: X.X.X.X/X
    if [[ "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        # Further check: Verify netmask is <= 32
        local cidr=${ip_cidr##*/}
        if [ "$cidr" -gt 32 ]; then return 1; fi
        return 0
    else
        return 1
    fi
}

get_available_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | tr '\n' ' '
}

get_current_ip() {
    local iface="$1"
    ip -4 addr show dev "$iface" | awk '/inet / {print $2}'
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

    local target_ip="${target_ip_cidr%%/*}"
    local target_cidr="${target_ip_cidr##*/}"
    local target_mask=$(cidr_to_netmask "$target_cidr")

    if [ "$change_type" = "ip" ] || [ "$change_type" = "gateway" ]; then
        if command -v ip >/dev/null 2>&1; then
            echo "Using ip command to revert $change_type..."
            ip addr flush dev "$iface"
            # If this command fails due to invalid IP, it logs to stderr but won't crash the script
            ip addr add "$target_ip_cidr" dev "$iface"
            ip link set "$iface" up
            ip route del default 2>/dev/null
            ip route add default via "$target_gw"
        elif command -v ifconfig >/dev/null 2>&1; then
            echo "Using ifconfig to revert $change_type..."
            ifconfig "$iface" "$target_ip" netmask "$target_mask" up
            route del default 2>/dev/null
            route add default gw "$target_gw"
        else
            echo "[$timestamp] CRITICAL: No network tools found to revert changes." >> "$log_file"
            return 1
        fi
    fi

    if [ "$change_type" = "dns" ]; then
        echo "[$timestamp] Editing /etc/resolv.conf to revert DNS..." >> "$log_file"
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
        iptables-save > "$iptables_file" || { echo -e "${RED}Error backing up iptables.${NC}"; return 1; }
        echo -e "${GREEN}iptables rules backed up to $iptables_file.${NC}"
    else
        echo -e "${YELLOW}iptables not available (kernel module missing?). Skipping backup.${NC}"
    fi
}

backup_routes() {
    ip route show > "$routes_file" || { echo -e "${RED}Error backing up routes.${NC}"; return 1; }
    echo -e "${GREEN}Route table backed up to $routes_file.${NC}"
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

check_root
# Resolve dependencies immediately upon start
resolve_dependencies

# --- INSTALLATION MODE ---
if [ "$1" = "--install" ]; then

    echo -e "${YELLOW}Starting Alpine installation/update mode...${NC}"

    mkdir -p /etc/IntProc

    INTERFACE=""
    IP=""
    GATEWAY=""
    DNS=""
    UPDATE_ONLY="no"

    if [ -f "$config_file" ]; then
        source "$config_file"
        echo -e "${GREEN}Existing config found. Entering update mode.${NC}"
        UPDATE_ONLY="yes"
    fi

    cp "$0" /usr/local/bin/IntProc.sh
    chmod +x /usr/local/bin/IntProc.sh
    echo -e "${GREEN}Script copied to /usr/local/bin/IntProc.sh.${NC}"

    if [ "$UPDATE_ONLY" = "no" ]; then
        echo -e "${YELLOW}Detecting available network interfaces...${NC}"
        available_ifaces=$(get_available_interfaces)
        interfaces=($available_ifaces)
        echo "Available interfaces:"
        for i in "${!interfaces[@]}"; do
            echo "$((i+1)). ${interfaces[i]}"
        done
        
        while true; do
            read -p "Enter the number of the interface to protect: " num
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#interfaces[@]}" ]; then
                interface="${interfaces[$((num-1))]}"
                break
            else
                echo -e "${RED}Invalid selection. Try again.${NC}"
            fi
        done
    else
        read -p "Enter the interface to protect [$INTERFACE]: " interface
        interface=${interface:-$INTERFACE}
    fi

    current_ip=$(get_current_ip "$interface")
    
    # FIX 3: Validated Input Loop for IP
    while true; do
        read -p "Enter static IP/CIDR (e.g. 192.168.1.100/24) [$IP or $current_ip]: " input_ip
        final_ip=${input_ip:-${IP:-$current_ip}}
        
        if validate_cidr "$final_ip"; then
            ip="$final_ip"
            break
        else
            echo -e "${RED}Invalid IP/CIDR format. Format must be X.X.X.X/XX (max /32).${NC}"
        fi
    done

    current_gw=$(get_current_gateway)
    read -p "Enter default gateway [$GATEWAY or $current_gw]: " gw
    gw=${gw:-${GATEWAY:-$current_gw}}

    current_dns=$(get_current_dns "$interface")
    read -p "Enter DNS servers [$DNS or $current_dns]: " dns
    dns=${dns:-${DNS:-$current_dns}}

    read -p "Backup iptables? (y/n) [y]: " backup_ipt
    [ "${backup_ipt:-y}" = "y" ] && backup_iptables

    read -p "Backup routes? (y/n) [y]: " backup_rts
    [ "${backup_rts:-y}" = "y" ] && backup_routes

    cat <<EOF > "$config_file"
INTERFACE="$interface"
IP="$ip"
GATEWAY="$gw"
DNS="$dns"
IPTABLES_FILE="$iptables_file"
ROUTES_FILE="$routes_file"
EOF
    echo -e "${GREEN}Configuration saved to $config_file.${NC}"

    if [ "$UPDATE_ONLY" = "no" ]; then
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
        echo -e "${GREEN}OpenRC init script created at /etc/init.d/intproc.${NC}"

        rc-update add intproc default
        rc-service intproc start
        echo -e "${GREEN}Service added to default runlevel and started.${NC}"
    else
        rc-service intproc restart
        echo -e "${GREEN}Service restarted.${NC}"
    fi

    echo -e "${YELLOW}Check status with: rc-service intproc status${NC}"
    exit 0
fi

# --- MONITORING MODE ---
if [ ! -f "$config_file" ]; then
    echo "Error: Configuration file not found. Run with --install first."
    exit 1
fi
source "$config_file"

touch "$log_file"
chmod 644 "$log_file"

while true; do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    if ! ip link show "$INTERFACE" up >/dev/null 2>&1; then
        echo "[$timestamp] Interface $INTERFACE is down. Bringing up." >> "$log_file"
        ip link set "$INTERFACE" up 2>> "$log_file"
    fi

    current_ip=$(get_current_ip "$INTERFACE")
    current_gw=$(get_current_gateway)
    current_dns=$(get_current_dns "$INTERFACE")
    log_gw="${current_gw:-none}"

    if [ "$current_ip" != "$IP" ]; then
        echo "[$timestamp] IP changed ($IP -> $current_ip). Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "ip"
    fi

    if [ "$current_gw" != "$GATEWAY" ]; then
        echo "[$timestamp] Gateway changed ($GATEWAY -> $log_gw). Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "gateway"
    fi

    # Flatten DNS for comparison
    flat_current_dns=$(echo "$current_dns" | xargs)
    flat_target_dns=$(echo "$DNS" | xargs)
    if [ "$flat_current_dns" != "$flat_target_dns" ]; then
        echo "[$timestamp] DNS changed ($flat_target_dns -> $flat_current_dns). Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "dns"
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
            echo "[$timestamp] Route table changed. Reverting." >> "$log_file"
            ip route flush table main
            while IFS= read -r line; do
                [ -n "$line" ] && ip route add $line 2>> "$log_file"
            done < "$ROUTES_FILE"
        fi
    fi

    sleep 5
done