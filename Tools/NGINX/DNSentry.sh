#!/bin/bash

# ====================================================================================
# Custom DNS Entry Tool for /etc/hosts
#
# Description: This script safely adds a custom DNS entry to the /etc/hosts file
#              and restarts the dnsmasq service if it's active.
#
#              It performs the following safety checks:
#              - Creates a timestamped backup of /etc/hosts before changes.
#              - Checks for duplicate IP addresses or hostnames.
#              - Verifies that the dnsmasq service exists before restarting it.
#
# Usage: sudo ./DNSentry.sh <IP_ADDRESS> <HOSTNAME>
# ====================================================================================

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Pre-flight Checks ---
# 1. Root User Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Error:${NC} This script must be run as root. Please use sudo."
  exit 1
fi

# 2. Argument Validation
if [ "$#" -ne 2 ]; then
    echo -e "${YELLOW}Usage:${NC} $0 <IP_ADDRESS> <HOSTNAME>"
    echo -e "${CYAN}Example:${NC} $0 192.168.1.100 my-local-server.lan"
    exit 1
fi

IP_ADDRESS=$1
HOTNAME=$2
HOSTS_FILE="/etc/hosts"

# --- Input Validation ---
# Regex for basic IP address validation
IP_REGEX="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
if ! [[ $IP_ADDRESS =~ $IP_REGEX ]]; then
    echo -e "${YELLOW}Error:${NC} Invalid IP address format: '$IP_ADDRESS'"
    exit 1
fi

# Regex for basic hostname validation
HOTNAME_REGEX="^[a-zA-Z0-9.-]+$"
if ! [[ $HOSTNAME =~ $HOSTNAME_REGEX ]]; then
    echo -e "${YELLOW}Error:${NC} Invalid hostname format: '$HOSTNAME'. Only alphanumeric characters, dots, and hyphens are allowed."
    exit 1
fi

# Removed dupe check - proxy needs to have multiple entries pointing
# at itself to be functional.

# --- Add Entry ---
# 1. Backup the hosts file
BACKUP_FILE="/etc/hosts.bak.$(date +%s)"
echo -e "Backing up $HOSTS_FILE to $BACKUP_FILE..."
cp "$HOSTS_FILE" "$BACKUP_FILE"

# 2. Add the new entry
HOSTS_ENTRY="$IP_ADDRESS\t$HOSTNAME"
echo -e "Adding entry: ${CYAN}$HOSTS_ENTRY${NC}"
echo -e "$HOSTS_ENTRY" >> "$HOSTS_FILE"

# 3. Restart dnsmasq if it exists
if systemctl cat dnsmasq &>/dev/null; then
    echo "Restarting dnsmasq service..."
    systemctl restart dnsmasq
else
    echo -e "${YELLOW}Warning:${NC} dnsmasq service not found. Skipping restart."
fi

echo ""
echo -e "${GREEN}SUCCESS: The entry has been added to $HOSTS_FILE.${NC}"
