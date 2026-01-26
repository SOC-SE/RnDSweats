#!/usr/bin/env bash

# IntProc - A self-contained Bash script for network interface protection.
# This script operates in two modes:
# 1. Installation mode (--install): Sets up the script as a systemd service. If config exists, enters update mode.
# 2. Monitoring mode (no arguments): Monitors and reverts network changes, including iptables and routes.
#
#    Designed by Samuel Brucker 2025-2026. AI was used for some of this script.
#
#

# Color codes for output (used in install mode)
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
NC="\e[0m"

# Config and log files
config_file="/etc/IntProc/IntProc.conf"
log_file="/var/log/IntProc.log"
iptables_file="/etc/IntProc/iptables.rules"
routes_file="/etc/IntProc/routes.txt"

# Make sure this is being ran as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root (use sudo).${NC}"
        exit 1
    fi
}

# Get the interfaces (thanks Gemini for the assist here)
get_available_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | tr '\n' ' '
}

# Get the IP and CIDR (not to be confused with the netmask)
get_current_ip() {
    local iface="$1"
    ip -4 addr show dev "$iface" | grep -oP '(?<=inet\s)\K\d{1,3}(\.\d{1,3}){3}/\d{1,2}(?=\s)'
}

# Get the gateway
get_current_gateway() {
    ip route show default | awk '/default/ {print $3}' | head -1
}

# See if systemd-resolved is active
is_resolved_active() {
    systemctl is-active --quiet systemd-resolved
}

# Get the DNS servers
get_current_dns() {
    local iface="$1"
    if command -v resolvectl >/dev/null 2>&1 && is_resolved_active; then
        resolvectl status "$iface" | awk '/DNS Servers:/ {for (i=3; i<=NF; i++) printf "%s ", $i; print ""}' | xargs
    else
        grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ' | xargs
    fi
}

# Convert the CIDR to netmask
cidr_to_netmask() {
    local cidr="$1"
    local mask=0xffffffff
    mask=$((mask << (32 - cidr)))
    printf "%d.%d.%d.%d\n" $((mask >> 24 & 255)) $((mask >> 16 & 255)) $((mask >> 8 & 255)) $((mask & 255))
}

# Function to revert network settings using the prioritized tool
# Thanks Gemini for cleaning this up and making it actually work!
revert_settings() {
    local iface="$1"
    local target_ip_cidr="$2"  # e.g., 192.168.1.100/24
    local target_gw="$3"
    local target_dns="$4"      # space-separated
    local change_type="$5"     # "ip", "gateway", or "dns"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Parse IP and CIDR
    local target_ip="${target_ip_cidr%%/*}"
    local target_cidr="${target_ip_cidr##*/}"
    local target_mask
    target_mask=$(cidr_to_netmask "$target_cidr")

    # Prioritize tools for IP and gateway: nmcli > ip > ifconfig
    if [ "$change_type" = "ip" ] || [ "$change_type" = "gateway" ]; then
        if command -v nmcli >/dev/null 2>&1; then
            echo "Using nmcli to revert $change_type..."
            local con_name
            con_name=$(nmcli dev status | grep "^$iface" | awk '{print $4}')
            if [ -z "$con_name" ] || [ "$con_name" = "--" ]; then
                # Log deleted/missing profile and recreate
                echo "[$timestamp] Connection profile for $iface deleted or missing. Recreating." >> "$log_file"
                nmcli con add con-name "net-defender-$iface" type ethernet ifname "$iface" ipv4.method manual ipv4.addresses "$target_ip_cidr" ipv4.gateway "$target_gw" ipv4.dns "$target_dns"
                con_name="net-defender-$iface"
            else
                nmcli con mod "$con_name" ipv4.addresses "$target_ip_cidr" ipv4.gateway "$target_gw" ipv4.dns "$target_dns" ipv4.method manual
            fi
            nmcli con up "$con_name" || { echo "[$timestamp] Failed to bring up connection $con_name." >> "$log_file"; return 1; }
        elif command -v ip >/dev/null 2>&1; then
            echo "Using ip command to revert $change_type..."
            ip addr flush dev "$iface"
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
            echo "[$timestamp] No suitable tool (nmcli, ip, ifconfig) found to revert changes." >> "$log_file"
            return 1
        fi
    fi

    # Handle DNS reversion separately
    if [ "$change_type" = "dns" ]; then
        if command -v nmcli >/dev/null 2>&1; then
            # Already handled in nmcli above, but ensure
            :
        elif command -v resolvectl >/dev/null 2>&1 && is_resolved_active; then
            echo "Using resolvectl to revert DNS..."
            # shellcheck disable=SC2086  # Word splitting intentional for DNS list
            resolvectl dns "$iface" $target_dns
            resolvectl flush-caches
        else
            echo "[$timestamp] Editing /etc/resolv.conf to revert DNS..." >> "$log_file"
            : > /etc/resolv.conf
            IFS=' ' read -r -a dns_array <<< "$target_dns"
            for dns in "${dns_array[@]}"; do
                echo "nameserver $dns" >> /etc/resolv.conf
            done
        fi
    fi
    return 0
}

# Backup the IP Tables
backup_iptables() {
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$iptables_file" || { echo -e "${RED}Error backing up iptables.${NC}"; return 1; }
        echo -e "${GREEN}iptables rules backed up to $iptables_file.${NC}"
    else
        echo -e "${YELLOW}iptables not available. Skipping backup.${NC}"
    fi
}

# Backup the route table
# Yes, this could be a little extreme, but I'm paranoid
backup_routes() {
    if command -v ip >/dev/null 2>&1; then
        ip route show > "$routes_file" || { echo -e "${RED}Error backing up routes.${NC}"; return 1; }
        echo -e "${GREEN}Route table backed up to $routes_file.${NC}"
    else
        echo -e "${YELLOW}ip command not available. Skipping routes backup.${NC}"
    fi
}

# Installation/Update mode
if [ "$1" = "--install" ]; then
    check_root

    echo -e "${YELLOW}Starting installation/update mode...${NC}"

    # Create config directory if needed
    mkdir -p /etc/IntProc

    # Default values (empty initially)
    INTERFACE=""
    IP=""
    GATEWAY=""
    DNS=""
    UPDATE_ONLY="no"

    # If config exists, load it and enter update mode
    if [ -f "$config_file" ]; then
        # shellcheck source=/dev/null
        source "$config_file"
        echo -e "${GREEN}Existing config found. Entering update mode.${NC}"
        echo "Current settings:"
        echo "INTERFACE: $INTERFACE"
        echo "IP: $IP"
        echo "GATEWAY: $GATEWAY"
        echo "DNS: $DNS"
        UPDATE_ONLY="yes"
    fi

    # Copy script to /usr/local/bin (always, in case of updates)
    cp "$0" /usr/local/bin/IntProc.sh
    chmod +x /usr/local/bin/IntProc.sh
    echo -e "${GREEN}Script copied to /usr/local/bin/IntProc.sh.${NC}"

    # Interactive configuration (prompt with current values as defaults)
    if [ "$UPDATE_ONLY" = "no" ]; then
        echo -e "${YELLOW}Detecting available network interfaces...${NC}"
        available_ifaces=$(get_available_interfaces)
        # shellcheck disable=SC2206  # Word splitting intentional for interface list
        interfaces=($available_ifaces)
        echo "Available interfaces:"
        for i in "${!interfaces[@]}"; do
            echo "$((i+1)). ${interfaces[i]}"
        done
        read -r -p "Enter the number of the interface to protect: " num
        if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#interfaces[@]}" ]; then
            echo -e "${RED}Error: Invalid selection.${NC}"
            exit 1
        fi
        interface="${interfaces[$((num-1))]}"
    else
        read -r -p "Enter the interface to protect [$INTERFACE]: " interface
        interface=${interface:-$INTERFACE}
    fi

    current_ip=$(get_current_ip "$interface")
    read -r -p "Enter the correct static IPv4 address and subnet mask in CIDR notation (e.g., 192.168.1.100/24) [$IP or $current_ip]: " ip
    ip=${ip:-${IP:-$current_ip}}

    current_gw=$(get_current_gateway)
    read -r -p "Enter the correct default gateway [$GATEWAY or $current_gw]: " gw
    gw=${gw:-${GATEWAY:-$current_gw}}

    current_dns=$(get_current_dns "$interface")
    read -r -p "Enter space-separated list of DNS servers (e.g., '8.8.8.8 1.1.1.1') [$DNS or $current_dns]: " dns
    dns=${dns:-${DNS:-$current_dns}}

    # Backup iptables and routes (prompt to update/backup)
    read -r -p "Backup/update current iptables rules? (y/n) [y]: " backup_ipt
    backup_ipt=${backup_ipt:-y}
    if [ "$backup_ipt" = "y" ]; then
        backup_iptables
    fi

    read -r -p "Backup/update current route table? (y/n) [y]: " backup_rts
    backup_rts=${backup_rts:-y}
    if [ "$backup_rts" = "y" ]; then
        backup_routes
    fi

    # Save config
    #You already know Gemini was involved here lol
    cat <<EOF > "$config_file"
INTERFACE="$interface"
IP="$ip"
GATEWAY="$gw"
DNS="$dns"
IPTABLES_FILE="$iptables_file"
ROUTES_FILE="$routes_file"
EOF
    echo -e "${GREEN}Configuration saved/updated to $config_file.${NC}"

    # If not update-only, create systemd service
    if [ "$UPDATE_ONLY" = "no" ]; then
        cat <<EOF > /etc/systemd/system/intproc.service
[Unit]
Description=Network Interface Protector (IntProc)
After=network.target

[Service]
ExecStart=/usr/local/bin/IntProc.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        echo -e "${GREEN}Systemd service file created at /etc/systemd/system/intproc.service.${NC}"

        # Reload, enable, and start service
        systemctl daemon-reload
        if ! systemctl enable intproc.service; then
            echo -e "${RED}Error enabling service.${NC}"
            exit 1
        fi
        if ! systemctl start intproc.service; then
            echo -e "${RED}Error starting service.${NC}"
            exit 1
        fi
        echo -e "${GREEN}Service enabled and started successfully!${NC}"
    else
        # Restart service to apply updates
        systemctl restart intproc.service
        echo -e "${GREEN}Service restarted to apply updates.${NC}"
    fi

    echo -e "${YELLOW}Operation complete. Check service status with: sudo systemctl status intproc.service${NC}"
    exit 0
fi

# Monitoring mode (default)
if [ ! -f "$config_file" ]; then
    echo "Error: Configuration file $config_file not found. Run with --install first."
    exit 1
fi
# shellcheck source=/dev/null
source "$config_file"  # Loads INTERFACE, IP, GATEWAY, DNS, IPTABLES_FILE, ROUTES_FILE

touch "$log_file"  # Ensure log file exists
chmod 644 "$log_file"  # Secure permissions

while true; do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Check if interface is up
    if ! ip link show "$INTERFACE" up >/dev/null 2>&1; then
        echo "[$timestamp] Interface $INTERFACE is down or missing. Attempting to bring up." >> "$log_file"
        ip link set "$INTERFACE" up 2>> "$log_file"
    fi

    # Get current settings
    current_ip=$(get_current_ip "$INTERFACE")
    current_gw=$(get_current_gateway)
    current_dns=$(get_current_dns "$INTERFACE")

    # Handle empty current_gw for logging
    log_gw="${current_gw:-none}"

    # Compare and revert if necessary
    if [ "$current_ip" != "$IP" ]; then
        echo "[$timestamp] Change detected on $INTERFACE: IP changed from $IP to $current_ip. Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "ip"
    fi

    if [ "$current_gw" != "$GATEWAY" ]; then
        echo "[$timestamp] Change detected on $INTERFACE: Gateway changed from $GATEWAY to $log_gw. Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "gateway"
    fi

    if [ "$(echo "$current_dns" | xargs)" != "$(echo "$DNS" | xargs)" ]; then
        echo "[$timestamp] Change detected on $INTERFACE: DNS changed from $DNS to $current_dns. Reverting." >> "$log_file"
        revert_settings "$INTERFACE" "$IP" "$GATEWAY" "$DNS" "dns"
    fi

    # Check and revert iptables if backed up
    # shellcheck disable=SC2153  # IPTABLES_FILE loaded from config file
    if [ -f "$IPTABLES_FILE" ] && command -v iptables-save >/dev/null 2>&1; then
        current_ipt=$(iptables-save)
        saved_ipt=$(cat "$IPTABLES_FILE")
        if [ "$current_ipt" != "$saved_ipt" ]; then
            echo "[$timestamp] iptables rules changed. Reverting to backup." >> "$log_file"
            iptables-restore < "$IPTABLES_FILE" || echo "[$timestamp] Failed to restore iptables." >> "$log_file"
        fi
    fi

    # Check and revert route table if backed up
    # shellcheck disable=SC2153  # ROUTES_FILE loaded from config file
    if [ -f "$ROUTES_FILE" ] && command -v ip >/dev/null 2>&1; then
        current_routes=$(ip route show | sort)
        saved_routes=$(sort "$ROUTES_FILE")
        if [ "$current_routes" != "$saved_routes" ]; then
            echo "[$timestamp] Route table changed. Reverting to backup." >> "$log_file"
            ip route flush table main
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    # shellcheck disable=SC2086  # Word splitting intentional for route args
                    ip route add $line 2>> "$log_file" || echo "[$timestamp] Failed to add route: $line" >> "$log_file"
                fi
            done < "$ROUTES_FILE"
        fi
    fi

    sleep 5
done
