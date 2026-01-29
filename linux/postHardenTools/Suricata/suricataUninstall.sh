#!/bin/bash

# ==============================================================================
# Suricata Emergency Removal Script
#
# Description: Quickly stops Suricata, flushes all NFQUEUE iptables rules,
#              and optionally fully uninstalls Suricata. Designed for competition use
#              scenarios where Suricata may be breaking scored services.
#
# Usage: sudo ./suricataUninstall.sh
# ==============================================================================

set -euo pipefail

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo "======================================================================"
    echo -e " ${GREEN}$1${NC}"
    echo "======================================================================"
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

exit_with_error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

# --- Pre-flight ---
if [ "$EUID" -ne 0 ]; then
    exit_with_error "This script must be run as root. Please use sudo."
fi

# Detect OS family
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""}
else
    exit_with_error "Cannot determine OS from /etc/os-release."
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    OS_FAMILY="debian"
    PKG_MANAGER="apt-get"
elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* || " $OS_ID_LIKE " == *"centos"* ]]; then
    OS_FAMILY="redhat"
    if command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
else
    print_warning "Unknown OS family. Will attempt generic removal."
    OS_FAMILY="unknown"
    PKG_MANAGER=""
fi

# =====================================================================
# STEP 1: Flush NFQUEUE iptables rules IMMEDIATELY
# This is the most critical step — restores network traffic even if
# everything else fails.
# =====================================================================
print_header "Step 1: Flushing NFQUEUE iptables rules"

# Remove specific NFQUEUE rules first (safer than full flush)
for chain in INPUT OUTPUT FORWARD; do
    while iptables -C "$chain" -j NFQUEUE --queue-num 0 2>/dev/null; do
        iptables -D "$chain" -j NFQUEUE --queue-num 0
        echo "  Removed NFQUEUE rule from $chain"
    done
    while iptables -C "$chain" -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do
        iptables -D "$chain" -j NFQUEUE --queue-num 0 --queue-bypass
        echo "  Removed NFQUEUE --queue-bypass rule from $chain"
    done
done

echo -e "${GREEN}NFQUEUE rules removed. Network traffic restored.${NC}"

# Save cleaned rules so they don't come back on reboot
case "$OS_FAMILY" in
    "debian")
        if [ -f /etc/iptables/rules.v4 ]; then
            iptables-save > /etc/iptables/rules.v4
            echo "  Saved cleaned rules to /etc/iptables/rules.v4"
        fi
        ;;
    "redhat")
        if [ -f /etc/sysconfig/iptables ]; then
            iptables-save > /etc/sysconfig/iptables
            echo "  Saved cleaned rules to /etc/sysconfig/iptables"
        fi
        ;;
esac

# =====================================================================
# STEP 2: Stop Suricata
# =====================================================================
print_header "Step 2: Stopping Suricata"

# Stop the systemd service
if systemctl is-active --quiet suricata 2>/dev/null; then
    systemctl stop suricata
    echo "  Suricata service stopped."
else
    echo "  Suricata service was not running."
fi

# Stop any Docker container version too
if command -v docker &>/dev/null; then
    if docker ps -q -f name=suricata 2>/dev/null | grep -q .; then
        docker stop suricata 2>/dev/null || true
        docker rm suricata 2>/dev/null || true
        echo "  Suricata Docker container stopped and removed."
    fi
fi

# Disable the service so it doesn't start on reboot
systemctl disable suricata 2>/dev/null || true
echo -e "${GREEN}Suricata stopped and disabled.${NC}"

# =====================================================================
# STEP 3: Ask whether to fully uninstall
# =====================================================================
print_header "Step 3: Uninstall Suricata packages?"
echo "Suricata is stopped and iptables rules are cleared."
echo "You can leave it installed (just disabled) or fully remove it."
echo " "
read -r -p "Fully uninstall Suricata? (y/n): " UNINSTALL

if [[ "$UNINSTALL" == [yY] ]]; then
    echo "Removing Suricata packages..."
    case "$OS_FAMILY" in
        "debian")
            $PKG_MANAGER remove -y suricata suricata-update 2>/dev/null || true
            $PKG_MANAGER autoremove -y 2>/dev/null || true
            ;;
        "redhat")
            $PKG_MANAGER remove -y suricata 2>/dev/null || true
            ;;
        *)
            print_warning "Unknown package manager. Attempting generic removal."
            command -v apt-get &>/dev/null && apt-get remove -y suricata 2>/dev/null || true
            command -v dnf &>/dev/null && dnf remove -y suricata 2>/dev/null || true
            command -v yum &>/dev/null && yum remove -y suricata 2>/dev/null || true
            ;;
    esac

    # Clean up config and PID files
    rm -f /var/run/suricata.pid

    echo " "
    read -r -p "Also remove config files and logs? (/etc/suricata, /var/log/suricata) (y/n): " PURGE
    if [[ "$PURGE" == [yY] ]]; then
        rm -rf /etc/suricata
        rm -rf /var/log/suricata
        rm -rf /var/lib/suricata
        echo "  Config, logs, and rule data removed."
    else
        echo "  Config and logs preserved."
    fi

    echo -e "${GREEN}Suricata fully uninstalled.${NC}"
else
    echo "Suricata left installed but disabled. Re-enable with:"
    echo "  systemctl enable --now suricata"
fi

print_header "Done"
echo "Network traffic is flowing normally. Scored services should be reachable."
