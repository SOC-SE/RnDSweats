#!/bin/bash
#
# Block IP - Quickly block an IP address via iptables
# Usage: sudo ./block-ip.sh <IP_ADDRESS>
#        sudo ./block-ip.sh --unblock <IP_ADDRESS>
#
set -eu

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Error: This script must be run as root.${NC}" >&2
    exit 1
fi

# Usage
usage() {
    echo "Usage: $0 <IP_ADDRESS>"
    echo "       $0 --unblock <IP_ADDRESS>"
    echo "       $0 --list"
    echo ""
    echo "Options:"
    echo "  --unblock    Remove block for specified IP"
    echo "  --list       Show currently blocked IPs"
    exit 1
}

# Validate IPv4 address format
validate_ip() {
    local ip="$1"

    # Check basic format (with optional CIDR)
    if ! echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
        return 1
    fi

    # Extract IP part (without CIDR if present)
    local ip_part="${ip%/*}"

    # Validate each octet is 0-255
    local IFS='.'
    # shellcheck disable=SC2086  # Word splitting intentional here
    set -- $ip_part
    for octet in "$1" "$2" "$3" "$4"; do
        if [ "$octet" -gt 255 ] 2>/dev/null || [ "$octet" -lt 0 ] 2>/dev/null; then
            return 1
        fi
        # Check it's actually a number
        case "$octet" in
            ''|*[!0-9]*) return 1 ;;
        esac
    done

    # Validate CIDR if present
    if echo "$ip" | grep -q '/'; then
        local cidr="${ip#*/}"
        if [ "$cidr" -gt 32 ] 2>/dev/null || [ "$cidr" -lt 0 ] 2>/dev/null; then
            return 1
        fi
    fi

    return 0
}

# Block an IP
block_ip() {
    local ip_addr="$1"

    if ! validate_ip "$ip_addr"; then
        echo "${RED}Error: Invalid IP address format: $ip_addr${NC}" >&2
        echo "Expected format: x.x.x.x or x.x.x.x/cidr" >&2
        exit 1
    fi

    # Check if already blocked
    if iptables -C INPUT -s "$ip_addr" -j DROP 2>/dev/null; then
        echo "${RED}IP $ip_addr is already blocked.${NC}"
        exit 0
    fi

    # Block incoming traffic FROM this IP
    iptables -I INPUT 1 -s "$ip_addr" -j DROP
    # Block forwarded traffic FROM this IP
    iptables -I FORWARD 1 -s "$ip_addr" -j DROP
    # Block outgoing traffic TO this IP
    iptables -I OUTPUT 1 -d "$ip_addr" -j DROP

    echo "${GREEN}Blocked: $ip_addr (INPUT, FORWARD, OUTPUT)${NC}"
    echo "Note: Rules are not persistent. Save with:"
    echo "  Debian/Ubuntu: netfilter-persistent save"
    echo "  RHEL/CentOS:   service iptables save"
    echo "  Alpine:        /etc/init.d/iptables save"
}

# Unblock an IP
unblock_ip() {
    local ip_addr="$1"

    if ! validate_ip "$ip_addr"; then
        echo "${RED}Error: Invalid IP address format: $ip_addr${NC}" >&2
        exit 1
    fi

    local removed=0

    # Remove from INPUT
    while iptables -D INPUT -s "$ip_addr" -j DROP 2>/dev/null; do
        removed=1
    done

    # Remove from FORWARD
    while iptables -D FORWARD -s "$ip_addr" -j DROP 2>/dev/null; do
        removed=1
    done

    # Remove from OUTPUT
    while iptables -D OUTPUT -d "$ip_addr" -j DROP 2>/dev/null; do
        removed=1
    done

    if [ "$removed" -eq 1 ]; then
        echo "${GREEN}Unblocked: $ip_addr${NC}"
    else
        echo "${RED}IP $ip_addr was not found in block rules.${NC}"
    fi
}

# List blocked IPs
list_blocked() {
    echo "=== Currently Blocked IPs (DROP rules) ==="
    echo ""
    echo "INPUT chain:"
    iptables -L INPUT -n --line-numbers | grep -E "DROP.*all.*--" | awk '{print "  " $0}' || echo "  (none)"
    echo ""
    echo "OUTPUT chain:"
    iptables -L OUTPUT -n --line-numbers | grep -E "DROP.*all.*--" | awk '{print "  " $0}' || echo "  (none)"
    echo ""
    echo "FORWARD chain:"
    iptables -L FORWARD -n --line-numbers | grep -E "DROP.*all.*--" | awk '{print "  " $0}' || echo "  (none)"
}

# Main
if [ $# -eq 0 ]; then
    usage
fi

case "${1:-}" in
    --unblock|-u)
        if [ -z "${2:-}" ]; then
            echo "${RED}Error: --unblock requires an IP address${NC}" >&2
            usage
        fi
        unblock_ip "$2"
        ;;
    --list|-l)
        list_blocked
        ;;
    --help|-h)
        usage
        ;;
    -*)
        echo "${RED}Unknown option: $1${NC}" >&2
        usage
        ;;
    *)
        block_ip "$1"
        ;;
esac
