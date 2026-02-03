#!/bin/bash
# ==============================================================================
# Salt Minion Installer for Salt-GUI
# Targets: Salt 3007 LTS
# ==============================================================================
#
# Based on original script by Samuel Brucker 2025-2026
# Modified for Salt-GUI integration
#
# Features:
# - Direct repository file creation (no dependency on repo RPM)
# - Supports both interactive and non-interactive (scripted) execution
# - Idempotent - safe to run multiple times
# - Retry logic for network operations
# - Better error handling and logging
# - Validation of inputs
# - Optional auto-accept key on master
#
# Usage:
#   Interactive:     sudo ./install-salt-minion.sh
#   Non-interactive: sudo ./install-salt-minion.sh -m 192.168.56.10 -i myminion
#   With auto-accept: sudo ./install-salt-minion.sh -m 192.168.56.10 -a
#
# ==============================================================================

set -euo pipefail

# --- Configuration ---
DEFAULT_MASTER_IP="172.20.242.20"
SALT_VERSION="3007"
MAX_RETRIES=3
RETRY_DELAY=5

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Logging Functions ---
log()   { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
debug() { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${BLUE}[DEBUG]${NC} $1" || true; }

die() {
    error "$1"
    exit "${2:-1}"
}

# --- Utility Functions ---
retry_command() {
    local cmd="$1"
    local description="${2:-command}"
    local attempt=1

    while [[ $attempt -le $MAX_RETRIES ]]; do
        log "Attempt $attempt/$MAX_RETRIES: $description"
        if eval "$cmd"; then
            return 0
        fi
        warn "Attempt $attempt failed. Retrying in ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
        ((attempt++))
    done

    error "All $MAX_RETRIES attempts failed for: $description"
    return 1
}

validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            [[ $octet -gt 255 ]] && return 1
        done
        return 0
    fi
    # Also allow hostnames
    if [[ $ip =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v apk &> /dev/null; then
        echo "apk"
    else
        echo "unknown"
    fi
}

get_el_version() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "fedora" ]]; then
            echo "9"  # Fedora uses RHEL 9 compatible repos
        elif [[ "$ID" == "amzn" ]]; then
            echo "9"  # Amazon Linux 2023 uses RHEL 9 compatible repos
        else
            echo "${VERSION_ID%%.*}"
        fi
    else
        rpm -E %rhel 2>/dev/null || echo "9"
    fi
}

# --- Installation Functions ---
setup_crypto_policy() {
    local pkg_mgr="$1"

    log "Configuring crypto policy for SHA-1 compatibility..."

    case "$pkg_mgr" in
        apt)
            if [[ -f /etc/ssl/openssl.cnf ]] && grep -q "SECLEVEL=2" /etc/ssl/openssl.cnf; then
                log "Lowering OpenSSL Security Level to allow SHA-1..."
                sed -i 's/SECLEVEL=2/SECLEVEL=1/g' /etc/ssl/openssl.cnf
            fi
            ;;
        dnf|yum)
            if command -v update-crypto-policies &> /dev/null; then
                log "Setting crypto policy to DEFAULT:SHA1..."
                update-crypto-policies --set DEFAULT:SHA1 2>/dev/null || true
            fi
            ;;
    esac
}

setup_apt_repo() {
    log "Setting up Salt repository for Debian/Ubuntu..."

    apt-get update -qq
    apt-get install -y -qq curl gnupg2

    mkdir -p /etc/apt/keyrings
    rm -f /etc/apt/keyrings/salt-archive-keyring.pgp

    retry_command \
        "curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public | tee /etc/apt/keyrings/salt-archive-keyring.pgp > /dev/null" \
        "Download Salt GPG key"

    # Verify GPG key was downloaded
    if [[ ! -s /etc/apt/keyrings/salt-archive-keyring.pgp ]]; then
        die "Failed to download Salt GPG key"
    fi

    local arch
    arch=$(dpkg --print-architecture)

    cat > /etc/apt/sources.list.d/salt.list <<EOF
deb [signed-by=/etc/apt/keyrings/salt-archive-keyring.pgp arch=$arch] https://packages.broadcom.com/artifactory/saltproject-deb/ stable main
EOF

    cat > /etc/apt/preferences.d/salt-pin-1001 <<EOF
Package: salt-*
Pin: version ${SALT_VERSION}.*
Pin-Priority: 1001
EOF

    apt-get update -qq
}

setup_rpm_repo() {
    local pkg_mgr="$1"
    local el_version
    el_version=$(get_el_version)

    log "Setting up Salt repository for RHEL/Fedora (EL${el_version})..."

    # Clean up old repos
    rpm -e --nodeps salt-repo 2>/dev/null || true
    rm -f /etc/yum.repos.d/salt*.repo

    # Download GPG key first
    log "Downloading Salt Project GPG key..."
    retry_command \
        "curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /tmp/salt-gpg-key.pub" \
        "Download Salt GPG key"

    # Verify GPG key was downloaded
    if [[ ! -s /tmp/salt-gpg-key.pub ]]; then
        die "Failed to download Salt GPG key"
    fi

    # Import GPG key
    log "Importing GPG key..."
    rpm --import /tmp/salt-gpg-key.pub

    # Create repository file directly
    log "Creating Salt repository configuration..."
    cat > /etc/yum.repos.d/salt.repo <<EOF
[saltproject-repo]
name=Salt Project Repository
baseurl=https://packages.broadcom.com/artifactory/saltproject-rpm/
enabled=1
gpgcheck=1
gpgkey=https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public
EOF

    log "Repository configuration created successfully"

    # Clean and rebuild cache
    $pkg_mgr clean all
    $pkg_mgr makecache || true
}

setup_apk_repo() {
    log "Setting up Salt for Alpine Linux..."

    # Alpine uses community packages
    apk update
    apk add --no-cache py3-pip python3 openssl

    # Install salt-minion via pip (Alpine doesn't have native salt packages)
    pip3 install --break-system-packages salt || pip3 install salt
}

install_salt_minion() {
    local pkg_mgr="$1"

    log "Installing Salt Minion..."

    case "$pkg_mgr" in
        apt)
            retry_command \
                "apt-get install -y -qq salt-minion" \
                "Install salt-minion package"
            ;;
        dnf|yum)
            retry_command \
                "$pkg_mgr install -y salt-minion" \
                "Install salt-minion package"
            ;;
        apk)
            log "Salt already installed via pip for Alpine"
            ;;
    esac
}

setup_auditd() {
    local pkg_mgr="$1"

    log "Setting up auditd with forensic watch rules..."

    case "$pkg_mgr" in
        apt)
            apt-get install -y -qq auditd audispd-plugins 2>/dev/null || apt-get install -y -qq auditd 2>/dev/null || true
            ;;
        dnf|yum)
            $pkg_mgr install -y -q audit 2>/dev/null || true
            ;;
        apk)
            apk add --quiet audit 2>/dev/null || true
            ;;
    esac

    # Write persistent audit rules
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/saltgui-forensics.rules << 'AUDITRULES'
## Salt-GUI forensic watch rules
-w /etc/passwd -p wa -k user_mod
-w /etc/shadow -p wa -k user_mod
-w /etc/sudoers -p wa -k sudo_mod
-w /etc/ssh/sshd_config -p wa -k ssh_mod
-w /etc/crontab -p wa -k cron_mod
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/pam.d/ -p wa -k pam_mod
-w /etc/ld.so.preload -p wa -k preload_mod
-w /etc/profile.d/ -p wa -k profile_mod
-w /etc/systemd/system/ -p wa -k systemd_mod
-a always,exit -F dir=/tmp -F perm=x -k tmp_exec
-a always,exit -F dir=/dev/shm -F perm=x -k shm_exec
AUDITRULES

    # Enable and start/restart auditd, load rules
    systemctl enable auditd 2>/dev/null || true
    # augenrules merges rules.d/ into audit.rules and loads them
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    log "Auditd configured with 12 forensic watch rules"
}

configure_minion() {
    local master_ip="$1"
    local minion_id="$2"

    log "Configuring Salt Minion..."

    # Stop service for configuration
    systemctl stop salt-minion 2>/dev/null || true

    # Create config directory
    mkdir -p /etc/salt/minion.d

    # Write master configuration
    cat > /etc/salt/minion.d/master.conf <<EOF
master: $master_ip
EOF

    # Set minion ID
    echo "$minion_id" > /etc/salt/minion_id

    # Remove any stale keys from previous installations
    rm -f /etc/salt/pki/minion/minion_master.pub 2>/dev/null || true

    log "Configuration complete: master=$master_ip, id=$minion_id"
}

start_minion_service() {
    log "Starting Salt Minion service..."

    systemctl daemon-reload
    systemctl enable salt-minion
    systemctl start salt-minion

    # Wait for service to stabilize
    sleep 3

    # Debian/Ubuntu often need a restart to properly connect
    if [[ -f /etc/debian_version ]]; then
        log "Performing stability restart (Debian/Ubuntu fix)..."
        sleep 2
        systemctl restart salt-minion
    fi

    # Verify service is running
    local attempts=0
    while [[ $attempts -lt 5 ]]; do
        if systemctl is-active --quiet salt-minion; then
            log "Salt Minion service is running."
            return 0
        fi
        ((attempts++))
        sleep 2
    done

    warn "Service may not be running properly. Check with: systemctl status salt-minion"
    return 1
}

# --- Parse Arguments ---
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Salt Minion Installer for Salt-GUI

Options:
    -m, --master IP     Salt Master IP address (default: $DEFAULT_MASTER_IP)
    -i, --id ID         Minion ID (default: system hostname)
    -d, --debug         Enable debug output
    -h, --help          Show this help message

Examples:
    $0                                    # Interactive mode
    $0 -m 192.168.56.10 -i webserver01   # Non-interactive
    $0 -m salt-master.local              # Using hostname

Supported Distributions:
    - Debian 11+, Ubuntu 20.04+
    - RHEL 8+, Rocky Linux 8+, AlmaLinux 8+, Oracle Linux 8+
    - Fedora 38+
    - CentOS Stream 8+
EOF
    exit 0
}

SALT_MASTER_IP=""
MINION_ID=""
INTERACTIVE=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--master)
            SALT_MASTER_IP="$2"
            INTERACTIVE=false
            shift 2
            ;;
        -i|--id)
            MINION_ID="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "Unknown option: $1. Use -h for help."
            ;;
    esac
done

# --- Main Execution ---
main() {
    echo "#####################################################"
    echo "# Salt Minion Installer for Salt-GUI                #"
    echo "# Salt Version: ${SALT_VERSION} LTS                           #"
    echo "#####################################################"
    echo

    # Root check
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root. Try: sudo $0"
    fi

    # Detect package manager
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    if [[ "$pkg_mgr" == "unknown" ]]; then
        die "No supported package manager found (apt/dnf/yum required)"
    fi
    log "Detected package manager: $pkg_mgr"

    # Get master IP
    if [[ -z "$SALT_MASTER_IP" ]]; then
        if [[ "$INTERACTIVE" == "true" ]]; then
            read -rp "Enter Salt Master IP [Default: $DEFAULT_MASTER_IP]: " SALT_MASTER_IP
        fi
        SALT_MASTER_IP="${SALT_MASTER_IP:-$DEFAULT_MASTER_IP}"
    fi

    if ! validate_ip "$SALT_MASTER_IP"; then
        die "Invalid IP address or hostname: $SALT_MASTER_IP"
    fi
    log "Master IP: $SALT_MASTER_IP"

    # Get minion ID
    if [[ -z "$MINION_ID" ]]; then
        local default_id
        default_id=$(hostname -s 2>/dev/null || hostname)
        if [[ "$INTERACTIVE" == "true" ]]; then
            read -rp "Enter Minion ID [Default: $default_id]: " MINION_ID
        fi
        MINION_ID="${MINION_ID:-$default_id}"
    fi
    log "Minion ID: $MINION_ID"

    # Check for existing installation
    if systemctl is-active --quiet salt-minion 2>/dev/null; then
        warn "Salt Minion is already running. Stopping for reconfiguration..."
        systemctl stop salt-minion
    fi

    # Setup crypto policy
    setup_crypto_policy "$pkg_mgr"

    # Setup repository
    case "$pkg_mgr" in
        apt)
            setup_apt_repo
            ;;
        dnf|yum)
            setup_rpm_repo "$pkg_mgr"
            ;;
        apk)
            setup_apk_repo
            ;;
    esac

    # Install minion
    install_salt_minion "$pkg_mgr"

    # Setup auditd for forensic monitoring
    setup_auditd "$pkg_mgr"

    # Configure minion
    configure_minion "$SALT_MASTER_IP" "$MINION_ID"

    # Start service
    start_minion_service

    # Summary
    echo
    echo "#####################################################"
    echo "# MINION SETUP COMPLETE                             #"
    echo "#####################################################"
    echo "Minion ID:  $MINION_ID"
    echo "Master IP:  $SALT_MASTER_IP"
    echo "Status:     $(systemctl is-active salt-minion 2>/dev/null || echo 'unknown')"
    echo "#####################################################"
    echo
    echo "Next steps:"
    echo "  1. Accept the key on the master:"
    echo "     salt-key -a '$MINION_ID'"
    echo "  2. Or accept all pending keys:"
    echo "     salt-key -A"
    echo "  3. Test connectivity:"
    echo "     salt '$MINION_ID' test.ping"
}

main "$@"
