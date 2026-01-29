#!/bin/sh
# ==============================================================================
# Script Name: intProc.sh
# Description: Network Interface Protector - Self-healing network defense system
#              Monitors and reverts unauthorized changes to IP, gateway, DNS,
#              iptables rules, and routes. Supports systemd and OpenRC.
# Author: CCDC Team (Samuel Brucker 2025-2026)
# Date: 2025-2026
# Version: 3.0
#
# Usage:
#   ./intProc.sh [options]
#
# Options:
#   --install     Install the service and configure initial settings
#   --toggle      Switch between Maintenance Mode (pause) and Protection (resume)
#   --update      Update the baseline to current system state
#   -h, --help    Show this help message
#
# Features:
#   - Multi-interface protection
#   - IP, Gateway, DNS monitoring and reversion
#   - iptables and route table protection
#   - Maintenance mode for making legitimate changes
#   - Auto-detects systemd vs OpenRC
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#   - Alpine Linux 3.x+
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Permission denied
#
# ==============================================================================

# Bootstrap: Ensure bash is available, install if needed (for Alpine)
if [ -z "$BASH_VERSION" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        echo "Bash not found. Attempting to install..."
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: Need root to install bash."
            exit 1
        fi
        if command -v apk >/dev/null 2>&1; then
            apk update && apk add bash || exit 1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y bash || exit 1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash || exit 1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash || exit 1
        fi
    fi
    exec bash "$0" "$@"
fi

# ==============================================================================
# BASH SCRIPT STARTS HERE
# ==============================================================================

set -uo pipefail

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
NC="\e[0m"

# Config and log files
CONFIG_DIR="/etc/IntProc"
CONFIG_FILE="$CONFIG_DIR/IntProc.conf"
LOG_FILE="/var/log/IntProc.log"
IPTABLES_FILE="$CONFIG_DIR/iptables.rules"
ROUTES_FILE="$CONFIG_DIR/routes.txt"
MAINTENANCE_FILE="$CONFIG_DIR/maintenance.lock"

# Detect init system
detect_init_system() {
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo "unknown"
    fi
}

INIT_SYSTEM=$(detect_init_system)

# --- Helper Functions ---

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi
}

show_help() {
    echo -e "${CYAN}intProc - Network Interface Protector${NC}"
    echo ""
    echo "Usage: intProc.sh [OPTION]"
    echo ""
    echo "Options:"
    echo -e "  ${GREEN}--install${NC}   Install service and configure initial settings"
    echo -e "  ${GREEN}--toggle${NC}    Switch between Maintenance Mode and Protection"
    echo -e "              - Pausing: Stops protection for manual changes"
    echo -e "              - Resuming: Auto-saves current state as new baseline"
    echo -e "  ${GREEN}--update${NC}    Update baseline to current system state"
    echo -e "  ${GREEN}-h, --help${NC}  Show this help message"
    echo ""
    echo "Detected init system: $INIT_SYSTEM"
    exit 0
}

resolve_dependencies() {
    local packages_to_install=""
    local missing=0

    if ! command -v ip >/dev/null 2>&1; then packages_to_install="$packages_to_install iproute2"; missing=1; fi
    if ! command -v iptables >/dev/null 2>&1; then packages_to_install="$packages_to_install iptables"; missing=1; fi

    if [ $missing -eq 1 ]; then
        echo -e "${YELLOW}Installing missing dependencies: $packages_to_install${NC}"
        if command -v apk >/dev/null 2>&1; then
            apk update >/dev/null 2>&1
            # shellcheck disable=SC2086
            apk add --no-cache $packages_to_install
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -y >/dev/null 2>&1
            # shellcheck disable=SC2086
            apt-get install -y $packages_to_install
        elif command -v dnf >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            dnf install -y $packages_to_install
        elif command -v yum >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            yum install -y $packages_to_install
        fi
    fi
}

get_available_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | tr '\n' ' '
}

get_current_ip() {
    local iface="$1"
    ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet / {print $2}' | head -n 1
}

get_current_gateway() {
    ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1
}

is_resolved_active() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet systemd-resolved 2>/dev/null
    else
        return 1
    fi
}

get_current_dns() {
    local iface="$1"
    if command -v resolvectl >/dev/null 2>&1 && is_resolved_active; then
        resolvectl status "$iface" 2>/dev/null | awk '/DNS Servers:/ {for (i=3; i<=NF; i++) printf "%s ", $i; print ""}' | xargs
    else
        grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' | xargs
    fi
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
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    local target_ip="${target_ip_cidr%%/*}"
    local target_cidr="${target_ip_cidr##*/}"

    if [ "$change_type" = "ip" ]; then
        if command -v nmcli >/dev/null 2>&1; then
            local con_name
            con_name=$(nmcli dev status 2>/dev/null | grep "^$iface" | awk '{print $4}')
            if [ -z "$con_name" ] || [ "$con_name" = "--" ]; then
                echo "[$timestamp] Recreating connection for $iface" >> "$LOG_FILE"
                nmcli con add con-name "intproc-$iface" type ethernet ifname "$iface" \
                    ipv4.method manual ipv4.addresses "$target_ip_cidr" \
                    ipv4.gateway "$target_gw" ipv4.dns "$target_dns" 2>> "$LOG_FILE"
                con_name="intproc-$iface"
            else
                nmcli con mod "$con_name" ipv4.addresses "$target_ip_cidr" \
                    ipv4.gateway "$target_gw" ipv4.dns "$target_dns" ipv4.method manual 2>> "$LOG_FILE"
            fi
            nmcli con up "$con_name" 2>> "$LOG_FILE" || true
        elif command -v ip >/dev/null 2>&1; then
            ip addr flush dev "$iface" 2>> "$LOG_FILE"
            ip addr add "$target_ip_cidr" dev "$iface" 2>> "$LOG_FILE"
            ip link set "$iface" up 2>> "$LOG_FILE"
        fi
    fi

    if [ "$change_type" = "gateway" ]; then
        ip route del default 2>/dev/null || true
        ip route add default via "$target_gw" 2>> "$LOG_FILE" || true
    fi

    if [ "$change_type" = "dns" ]; then
        if command -v resolvectl >/dev/null 2>&1 && is_resolved_active; then
            # shellcheck disable=SC2086
            resolvectl dns "$iface" $target_dns 2>> "$LOG_FILE" || true
            resolvectl flush-caches 2>/dev/null || true
        else
            echo "[$timestamp] Reverting DNS in /etc/resolv.conf" >> "$LOG_FILE"
            : > /etc/resolv.conf
            for dns in $target_dns; do
                echo "nameserver $dns" >> /etc/resolv.conf
            done
        fi
    fi
}

backup_iptables() {
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$IPTABLES_FILE" 2>/dev/null
        echo -e "${GREEN}iptables rules backed up${NC}"
    fi
}

backup_routes() {
    if command -v ip >/dev/null 2>&1; then
        ip route show > "$ROUTES_FILE" 2>/dev/null
        echo -e "${GREEN}Route table backed up${NC}"
    fi
}

snapshot_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}Error: No config file. Run --install first.${NC}"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    echo -e "${CYAN}Snapshotting current system state...${NC}"

    local current_gw
    current_gw=$(get_current_gateway)
    local current_dns
    current_dns=$(get_current_dns "any")
    local temp_config="/tmp/IntProc_new.conf"

    echo "INTERFACES=\"$INTERFACES\"" > "$temp_config"
    echo "GATEWAY=\"$current_gw\"" >> "$temp_config"
    echo "DNS=\"$current_dns\"" >> "$temp_config"
    echo "IPTABLES_FILE=\"$IPTABLES_FILE\"" >> "$temp_config"
    echo "ROUTES_FILE=\"$ROUTES_FILE\"" >> "$temp_config"

    for iface in $INTERFACES; do
        local current_ip
        current_ip=$(get_current_ip "$iface")
        echo "IP_$iface=\"$current_ip\"" >> "$temp_config"
        echo "  - $iface: $current_ip"
    done

    mv "$temp_config" "$CONFIG_FILE"

    [ -f "$IPTABLES_FILE" ] && backup_iptables
    [ -f "$ROUTES_FILE" ] && backup_routes

    echo -e "${GREEN}Configuration updated!${NC}"
}

install_systemd_service() {
    cat > /etc/systemd/system/intproc.service << 'EOF'
[Unit]
Description=Network Interface Protector (IntProc)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/intProc.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable intproc.service
    systemctl start intproc.service
    echo -e "${GREEN}Systemd service installed and started${NC}"
}

install_openrc_service() {
    cat > /etc/init.d/intproc << 'EOF'
#!/sbin/openrc-run
name="intproc"
description="Network Interface Protector"
command="/bin/bash"
command_args="/usr/local/bin/intProc.sh"
command_background=true
pidfile="/run/intproc.pid"
depend() {
    need net
    after firewall
}
EOF

    chmod +x /etc/init.d/intproc
    rc-update add intproc default
    rc-service intproc restart
    echo -e "${GREEN}OpenRC service installed and started${NC}"
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

# Help can be shown without root
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
fi

check_root
resolve_dependencies

# --- Toggle Mode ---
if [ "${1:-}" = "--toggle" ]; then
    if [ -f "$MAINTENANCE_FILE" ]; then
        echo -e "${CYAN}Resuming protection and saving current state...${NC}"
        snapshot_config
        rm "$MAINTENANCE_FILE"
        echo -e "${GREEN}Protection RESUMED${NC}"
    else
        touch "$MAINTENANCE_FILE"
        echo -e "${YELLOW}Maintenance Mode ACTIVATED${NC}"
        echo "Protection paused. Make your changes, then run --toggle again."
    fi
    exit 0
fi

# --- Update Mode ---
if [ "${1:-}" = "--update" ]; then
    snapshot_config
    exit 0
fi

# --- Installation Mode ---
if [ "${1:-}" = "--install" ]; then
    echo -e "${YELLOW}Starting IntProc Installation...${NC}"
    mkdir -p "$CONFIG_DIR"

    # Select interfaces
    available_ifaces=$(get_available_interfaces)
    # shellcheck disable=SC2206
    interfaces=($available_ifaces)

    echo "Available interfaces:"
    for i in "${!interfaces[@]}"; do
        echo "$((i+1)). ${interfaces[i]}"
    done

    read -rp "Enter numbers of interfaces to protect (e.g. '1 2'): " selection
    selected_interfaces=""

    for num in $selection; do
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#interfaces[@]}" ]; then
            iface_name="${interfaces[$((num-1))]}"
            selected_interfaces="$selected_interfaces $iface_name"

            current_ip=$(get_current_ip "$iface_name")
            read -rp "IP/CIDR for $iface_name [$current_ip]: " final_ip
            final_ip=${final_ip:-$current_ip}
            echo "IP_$iface_name=\"$final_ip\"" >> "$CONFIG_FILE.tmp"
        fi
    done

    selected_interfaces=$(echo "$selected_interfaces" | xargs)
    echo "INTERFACES=\"$selected_interfaces\"" >> "$CONFIG_FILE.tmp"

    current_gw=$(get_current_gateway)
    read -rp "Gateway [$current_gw]: " gw
    echo "GATEWAY=\"${gw:-$current_gw}\"" >> "$CONFIG_FILE.tmp"

    current_dns=$(get_current_dns "any")
    read -rp "DNS servers (space-separated) [$current_dns]: " dns
    echo "DNS=\"${dns:-$current_dns}\"" >> "$CONFIG_FILE.tmp"

    echo "IPTABLES_FILE=\"$IPTABLES_FILE\"" >> "$CONFIG_FILE.tmp"
    echo "ROUTES_FILE=\"$ROUTES_FILE\"" >> "$CONFIG_FILE.tmp"

    mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"

    read -rp "Backup current iptables rules? [Y/n]: " backup_ipt
    [[ ! "$backup_ipt" =~ ^[Nn] ]] && backup_iptables

    read -rp "Backup current route table? [Y/n]: " backup_rts
    [[ ! "$backup_rts" =~ ^[Nn] ]] && backup_routes

    # Copy script to /usr/local/bin
    cp "$0" /usr/local/bin/intProc.sh
    chmod +x /usr/local/bin/intProc.sh

    # Install service based on init system
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        install_systemd_service
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        install_openrc_service
    else
        echo -e "${YELLOW}Unknown init system. Service not installed.${NC}"
        echo "Run /usr/local/bin/intProc.sh manually or create a service."
    fi

    echo -e "${GREEN}Installation complete!${NC}"
    echo "Check status: $([[ $INIT_SYSTEM == 'systemd' ]] && echo 'systemctl status intproc' || echo 'rc-service intproc status')"
    exit 0
fi

# --- Monitoring Mode (Daemon) ---
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Configuration not found. Run --install first.${NC}"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

echo "IntProc monitoring started at $(date)" >> "$LOG_FILE"

while true; do
    # Skip if in maintenance mode
    if [ -f "$MAINTENANCE_FILE" ]; then
        sleep 5
        continue
    fi

    # Reload config in case it changed
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"

    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Check gateway
    current_gw=$(get_current_gateway)
    if [ "$current_gw" != "$GATEWAY" ]; then
        echo "[$timestamp] Gateway changed from $GATEWAY to $current_gw. Reverting." >> "$LOG_FILE"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "gateway"
    fi

    # Check DNS
    current_dns=$(get_current_dns "any")
    if [ "$(echo "$current_dns" | xargs)" != "$(echo "$DNS" | xargs)" ]; then
        echo "[$timestamp] DNS changed. Reverting." >> "$LOG_FILE"
        revert_settings "global" "0.0.0.0/0" "$GATEWAY" "$DNS" "dns"
    fi

    # Check iptables
    if [ -f "$IPTABLES_FILE" ] && command -v iptables-save >/dev/null 2>&1; then
        current_ipt=$(iptables-save 2>/dev/null)
        saved_ipt=$(cat "$IPTABLES_FILE")
        if [ "$current_ipt" != "$saved_ipt" ]; then
            echo "[$timestamp] iptables changed. Reverting." >> "$LOG_FILE"
            iptables-restore < "$IPTABLES_FILE" 2>> "$LOG_FILE" || true
        fi
    fi

    # Check routes
    if [ -f "$ROUTES_FILE" ] && command -v ip >/dev/null 2>&1; then
        current_routes=$(ip route show | sort)
        saved_routes=$(sort "$ROUTES_FILE")
        if [ "$current_routes" != "$saved_routes" ]; then
            echo "[$timestamp] Routes changed. Reverting." >> "$LOG_FILE"
            ip route flush table main 2>/dev/null || true
            while IFS= read -r line; do
                [ -n "$line" ] && ip route add $line 2>> "$LOG_FILE" || true
            done < "$ROUTES_FILE"
        fi
    fi

    # Check per-interface IPs
    for iface in $INTERFACES; do
        target_ip_var="IP_$iface"
        target_ip="${!target_ip_var}"

        if ! ip link show "$iface" up >/dev/null 2>&1; then
            echo "[$timestamp] Interface $iface is down. Bringing up." >> "$LOG_FILE"
            ip link set "$iface" up 2>> "$LOG_FILE" || true
        fi

        current_ip=$(get_current_ip "$iface")
        if [ "$current_ip" != "$target_ip" ]; then
            echo "[$timestamp] IP on $iface changed from $target_ip to $current_ip. Reverting." >> "$LOG_FILE"
            revert_settings "$iface" "$target_ip" "$GATEWAY" "$DNS" "ip"
        fi
    done

    sleep 5
done
