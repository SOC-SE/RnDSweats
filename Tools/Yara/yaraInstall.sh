#!/bin/bash

# CCDC Development - Yara & JQ Installer (v2 - with SSL fix)
# This script installs Yara from source and jq from package managers.
# It automatically detects the OS (Debian/Ubuntu vs. RHEL/CentOS/Fedora)
# and installs the necessary dependencies.
# Includes a fix for SSL/TLS certificate validation errors during download.
# Run as root or with sudo.

set -e
set -o pipefail

# --- Variables ---
YARA_VERSION="4.5.1"
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
DOWNLOAD_DIR="/tmp/yara-build"
# Add wget flag to ignore certificate checks
WGET_FLAGS="--no-check-certificate"

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
        tar \
        ca-certificates
    # Attempt to update certificates as a best practice
    update-ca-certificates
    log "Dependencies installed successfully."
}

# Function to install dependencies on Red Hat-based systems
install_deps_redhat() {
    log "Detected Red Hat-based system. Installing dependencies..."
    local PKG_MANAGER
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        log "Could not find dnf or yum. Aborting."
        exit 1
    fi

    $PKG_MANAGER groupinstall -y "Development Tools"
    $PKG_MANAGER install -y openssl-devel file-devel jq wget tar ca-certificates

    $PKG_MANAGER install -y \
        gcc \
        make \
        automake \
        autoconf \
        libtool \
        openssl-devel \
        file-devel \
        jq \
        wget \
        tar \
        ca-certificates
    # Attempt to update certificates as a best practice
    update-ca-trust
    log "Dependencies installed successfully."
}

# Function to download and build Yara
build_yara() {
    log "Starting Yara v${YARA_VERSION} build process..."

    log "Creating build directory at ${DOWNLOAD_DIR}..."
    rm -rf "${DOWNLOAD_DIR}"
    mkdir -p "${DOWNLOAD_DIR}"
    cd "${DOWNLOAD_DIR}"

    log "Downloading Yara source from ${YARA_URL} (ignoring SSL cert check)..."
    wget -q -O yara.tar.gz "${YARA_URL}" ${WGET_FLAGS}
    tar -xzf yara.tar.gz
    cd yara-${YARA_VERSION}

    log "Compiling Yara... this may take a few minutes."
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet
    make -j"$(nproc)"
    make install
    
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

    if [ -f /etc/debian_version ]; then
        install_deps_debian
    elif [ -f /etc/redhat-release ]; then
        install_deps_redhat
    else
        log "Unsupported operating system."
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