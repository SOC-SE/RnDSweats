#!/bin/bash

# CCDC Development - Yara & JQ Installer
# This script installs Yara from source and jq from package managers.
# It automatically detects the OS (Debian/Ubuntu vs. RHEL/CentOS/Fedora)
# and installs the necessary dependencies.
# Run as root or with sudo.

set -e
set -o pipefail

# --- Variables ---
YARA_VERSION="4.5.1"
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
DOWNLOAD_DIR="/tmp/yara-build"

# --- Functions ---

# Function to print messages
log() {
    echo "[*] $1"
}

# Function to check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
       log "This script must be run as root. Aborting."
       exit 1
    fi
    log "Root privileges confirmed."
}

# Function to install dependencies on Debian-based systems
install_deps_debian() {
    log "Detected Debian-based system. Installing dependencies..."
    apt-get update -y
    apt-get install -y \
        build-essential \
        libssl-dev \
        automake \
        autoconf \
        libtool \
        pkg-config \
        jq \
        wget \
        tar
    log "Dependencies installed successfully."
}

# Function to install dependencies on Red Hat-based systems
install_deps_redhat() {
    log "Detected Red Hat-based system. Installing dependencies..."
    local PKG_MANAGER
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"#!/bin/bash

# ==============================================================================
# CCDC Development - Automated Yara Installer & Rule Sanitizer
#
# Description: Installs Yara, clones the Neo23x0/signature-base ruleset,
#              removes files that cause errors in standard Yara, and compiles
#              the remaining rules into a single production file.
# Author:      Samuel Brucker
# Version:     1.1 (Corrected)
# ==============================================================================
# --- Pre-flight Checks ---

# Check 1: Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

# --- Main Execution ---

echo "🚀 Starting automated Yara setup..."

# Install Dependencies (Yara & jq)
echo "--------------------------------------------------"
echo "STEP 1: Installing Yara and jq..."
echo "--------------------------------------------------"
if command -v apt-get &> /dev/null; then
    echo "🔎 Debian/Ubuntu based system detected. Using apt-get..."
    apt-get update -y > /dev/null 2>&1
    apt-get install yara jq -y
    
elif command -v dnf &> /dev/null; then
    echo "🔎 RHEL/Fedora based system detected. Using dnf..."
    dnf install yara jq -y
    
elif command -v yum &> /dev/null; then
    echo "🔎 RHEL/CentOS based system detected. Using yum..."
    yum install yara jq -y
    
else
    echo "❌ Unsupported package manager. Please install Yara and jq manually."
    exit 1
fi
echo "✅ Yara and jq installed successfully."
        openssl-devel \
        file-devel \
        jq \
        wget \
        tar
    log "Dependencies installed successfully."
}

# Function to download and build Yara
build_yara() {
    log "Starting Yara v${YARA_VERSION} build process..."

    # Create a clean directory for the build
    log "Creating build directory at ${DOWNLOAD_DIR}..."
    rm -rf "${DOWNLOAD_DIR}"
    mkdir -p "${DOWNLOAD_DIR}"
    cd "${DOWNLOAD_DIR}"

    # Download Yara source
    log "Downloading Yara source from ${YARA_URL}..."
    wget -q -O yara.tar.gz "${YARA_URL}"
    tar -xzf yara.tar.gz
    cd yara-${YARA_VERSION}

    # Compile and install
    log "Compiling Yara... this may take a few minutes."
    ./bootstrap.sh
    # We enable common modules for better functionality
    ./configure --enable-cuckoo --enable-magic --enable-dotnet
    make -j"$(nproc)"
    make install
    
    # Update the shared library cache
    ldconfig
    
    log "Yara installed successfully."
}

# Function for cleanup
cleanup() {
    log "Cleaning up build files..."
    rm -rf "${DOWNLOAD_DIR}"
    log "Cleanup complete."
}

# --- Main Execution ---
main() {
    check_root

    # Detect OS and install dependencies
    if [ -f /etc/debian_version ]; then
        install_deps_debian
    elif [ -f /etc/redhat-release ]; then
        install_deps_redhat
    else
        log "Unsupported operating system. This script supports Debian and Red Hat-based distributions."
        exit 1
    fi

    build_yara
    cleanup

    log "--- Installation Summary ---"
    if command -v yara &> /dev/null && command -v jq &> /dev/null; then
        echo "✅ SUCCESS: Yara and jq are installed."
        echo "   Yara version: $(yara --version)"
        echo "   jq version: $(jq --version)"
    else
        echo "❌ FAILURE: Installation could not be verified."
    fi
}

main "$@"