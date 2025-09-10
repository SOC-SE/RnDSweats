#!/bin/bash

# ====================================================================================
# Custom DNS Entry Generator for dnsmasq
#
# This script generates the command needed to add a custom DNS entry
# to the /etc/hosts file, which dnsmasq reads by default.
#
# It does NOT execute the command, preventing accidental or malicious changes.
# The user must manually copy and run the outputted command.
# ====================================================================================

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Input Validation ---
if [ "$#" -ne 2 ]; then
    echo -e "${YELLOW}Usage:${NC} $0 <IP_ADDRESS> <HOSTNAME>"
    echo -e "${CYAN}Example:${NC} $0 192.168.1.100 my-local-server.lan"
    exit 1
fi

IP_ADDRESS=$1
HOSTNAME=$2

# --- Regex for basic IP address validation ---
IP_REGEX="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
if ! [[ $IP_ADDRESS =~ $IP_REGEX ]]; then
    echo -e "${YELLOW}Error:${NC} Invalid IP address format: '$IP_ADDRESS'"
    exit 1
fi

# --- Regex for basic hostname validation ---
HOSTNAME_REGEX="^[a-zA-Z0-9.-]+$"
if ! [[ $HOSTNAME =~ $HOSTNAME_REGEX ]]; then
    echo -e "${YELLOW}Error:${NC} Invalid hostname format: '$HOSTNAME'. Only alphanumeric characters, dots, and hyphens are allowed."
    exit 1
fi

# --- Generate the Entry and Command ---
HOSTS_ENTRY="$IP_ADDRESS\t$HOSTNAME"

echo -e "${GREEN}SUCCESS: Your DNS entry has been generated.${NC}"
echo ""
echo -e "To apply this, run the following command with root privileges:"
echo -e "------------------------------------------------------------------"
echo -e "${CYAN}echo -e \"$HOSTS_ENTRY\" | sudo tee -a /etc/hosts${NC}"
echo -e "------------------------------------------------------------------"
echo ""
echo -e "After adding the entry, restart dnsmasq to ensure the change is applied immediately:"
echo -e "${CYAN}sudo systemctl restart dnsmasq${NC}"
