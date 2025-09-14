#!/bin/bash

# ====================================================================================
# FireJail Installation Script
#
# This script automates the installation of FireJail on Debian and Red Hat-based
# Linux distributions. It detects the OS and uses the appropriate package manager.
# ====================================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Function to Print Messages ---
log_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root. Please use sudo."
  exit 1
fi

# --- Step 1: System Detection ---
log_message "Detecting distribution and preparing for installation..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""} # Set to empty string if not defined
else
    log_warning "Cannot determine OS from /etc/os-release. Aborting."
    exit 1
fi

# Determine OS Family and set package manager
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    PKG_MANAGER="apt-get"
    log_message "Detected Debian-based system ($OS_ID). Using APT."
    log_message "Updating package lists..."
    $PKG_MANAGER update > /dev/null
elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* || " $OS_ID_LIKE " == *"centos"* ]]; then
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
    log_message "Detected Red Hat-based system ($OS_ID). Using $PKG_MANAGER."
    if [[ "$OS_ID" == "centos" || "$OS_ID" == "rhel" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "ol" ]]; then
        log_message "Ensuring EPEL repository is enabled for FireJail..."
        $PKG_MANAGER install -y epel-release > /dev/null
    fi
else
    log_warning "Unsupported distribution: '$OS_ID'. This script supports Debian and Red Hat families."
    exit 1
fi

# --- Step 2: Install FireJail ---
log_message "Installing FireJail..."
$PKG_MANAGER install -y firejail

# --- Step 3: Verification ---
log_message "Verifying FireJail installation..."
if command -v firejail &> /dev/null; then
    log_message "FireJail version:"
    firejail --version
    echo ""
    log_message "✅ FireJail installation complete and verified."
    
else
    log_warning "❌ FireJail installation could not be verified. Please check for errors."
    exit 1
fi

exit 0