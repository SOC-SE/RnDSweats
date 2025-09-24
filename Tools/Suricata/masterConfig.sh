#!/bin/bash

# --- Script Configuration ---
set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "======================================================================"
    echo -e " ${GREEN}$1${NC}"
    echo "======================================================================"
}

# Function to print an error message and exit
exit_with_error() {
    echo " "
    echo -e "${RED}[ERROR] $1${NC}" >&2
    echo "Aborting script."
    exit 1
}

# --- Pre-flight Checks ---

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
    exit_with_error "This script must be run as root. Please use sudo."
fi

# 2. Check for all required scripts
if [ ! -f ./suricataSetup.sh ]; then
	exit_with_error "suricataSetup.sh not found in this directory."
fi

if [ ! -f ./replaceDNS.sh ]; then
	exit_with_error "replaceDNS.sh not found in this directory"
fi

if [ ! -f ./NPMfresh.sh ]; then
	exit_with_error "NPMfresh.sh not found in this directory"
fi

# 3. Make sure all files are UNIX format EOF and can execute (make multi-PKM compatible later)
read -p "Set all files to UNIX EOF (currently only apt compatible)? (y/n) " yn
case $yn in
	[yY] ) 
		sudo apt install dos2unix
		find . -type f -name "*.sh" -print0 | xargs -0 dos2unix
		;;
	[nN] ) 
		echo "Skipping..."
		;;
esac


# Run DNS replacement
print_header "DNS Replacement"
read -p "Proceed with installation of dnsmasq? (y/n) " yn

case $yn in
	[yY] ) 
		sudo ./replaceDNS.sh;
		;;
	[nN] ) 
		echo "WARNING! NPM will not function without DNS records that point internally, dnsmasq is best solution..."
		echo "Skipping..."
		;;
esac

# Run NPM setup
print_header "Nginx Proxy Manager Setup"
read -p "Proceed with installation of Nginx Proxy Manager? (y/n) " yn

case $yn in
	[yY] ) 
		sudo ./NPMfresh.sh
		;;
	[nN] ) 
		echo "Skipping..."
		;;
esac

# Run suricata setup
print_header "Suricata Setup"
read -p "Proceed with installation of Suricata? (y/n) " yn

case $yn in
	[yY] ) 
		sudo ./suricataSetup.sh
		;;
	[nN] ) 
		echo "Skipping..."
		;;
esac

print_header "ALL PACKAGES INSTALLED SUCCESSFULLY"