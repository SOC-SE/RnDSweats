#!/bin/bash
# ==============================================================================
# Salt Minion Installer - Option 2+3: Fallback with Repository Verification
# Targets: Salt 3007 LTS
# ==============================================================================
#
# Improvements over original:
# - Repository access verification before installation
# - Fallback from repo RPM to direct configuration
# - Supports both interactive and non-interactive (scripted) execution
# - Idempotent - safe to run multiple times
# - Retry logic for network operations
# - Better error handling and logging
# - Validation of inputs
#
# Usage:
#   Interactive:     sudo ./linuxMinionInstall.sh
#   Non-interactive: sudo ./linuxMinionInstall.sh -m 172.20.242.20 -i myminion
#   With tools:      sudo ./linuxMinionInstall.sh -m 172.20.242.20 -t /path/to/tools
#
# Samuel Brucker 2025-2026
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
    else
        echo "unknown"
    fi
}

get_el_version() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "fedora" ]]; then
            echo "9"  # Fedora uses RHEL 9 compatible repos
        else
            echo "${VERSION_ID%%.*}"
        fi
    else
        rpm -E %rhel 2>/dev/null || echo "9"
    fi
}

# --- Repository Verification (Option 3) ---
verify_repo_access() {
    local el_version="$1"
    local test_url="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${el_version}/x86_64/${SALT_VERSION}/"
    
    log "Verifying repository access..."
    debug "Testing URL: $test_url"
    
    if curl -fsSL --connect-timeout 10 --max-time 30 --head "$test_url" > /dev/null 2>&1; then
        log "Repository is accessible"
        return 0
    else
        warn "Cannot access repository at: $test_url"
        return 1
    fi
}

verify_repo_rpm_exists() {
    local el_version="$1"
    local rpm_url="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${el_version}/x86_64/${SALT_VERSION}/salt-repo-${SALT_VERSION}-${el_version}.noarch.rpm"
    
    log "Checking if repository RPM exists..."
    debug "Testing RPM URL: $rpm_url"
    
    if curl -fsSL --connect-timeout 10 --max-time 30 --head "$rpm_url" > /dev/null 2>&1; then
        log "Repository RPM is available"
        return 0
    else
        warn "Repository RPM not found at: $rpm_url"
        return 1
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
                sed -i.bak 's/SECLEVEL=2/SECLEVEL=1/g' /etc/ssl/openssl.cnf
            fi
            ;;
        dnf|yum)
            if command -v update-crypto-policies &> /dev/null; then
                log "Setting crypto policy to DEFAULT:SHA1..."
                update-crypto-policies --set DEFAULT:SHA1
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

# --- RPM Repository Setup with Fallback (Option 2) ---
setup_rpm_repo_via_rpm() {
    local pkg_mgr="$1"
    local el_version="$2"
    local repo_url="https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${el_version}/x86_64/${SALT_VERSION}/salt-repo-${SALT_VERSION}-${el_version}.noarch.rpm"
    
    log "Attempting to install repository RPM..."
    debug "RPM URL: $repo_url"
    
    # Try to install the repo RPM
    if $pkg_mgr install -y "$repo_url" 2>&1 | tee /tmp/salt-repo-install.log; then
        log "Repository RPM installed successfully"
        $pkg_mgr clean expire-cache
        return 0
    else
        warn "Repository RPM installation failed"
        debug "Error log saved to /tmp/salt-repo-install.log"
        return 1
    fi
}

setup_rpm_repo_direct() {
    local pkg_mgr="$1"
    local el_version="$2"
    
    log "Setting up repository via direct configuration file..."
    
    # Download and import GPG key
    log "Downloading Salt Project GPG key..."
    if retry_command \
        "curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /tmp/salt-gpg-key.pub" \
        "Download Salt GPG key"; then
        
        # Verify GPG key was downloaded
        if [[ ! -s /tmp/salt-gpg-key.pub ]]; then
            die "Failed to download Salt GPG key"
        fi
        
        # Import GPG key
        log "Importing GPG key..."
        rpm --import /tmp/salt-gpg-key.pub
    else
        warn "Could not download GPG key, continuing with gpgcheck disabled"
        GPGCHECK=0
    fi
    
    # Create repository file directly
    log "Creating Salt repository configuration..."
    cat > /etc/yum.repos.d/salt.repo <<EOF
[saltproject-repo]
name=Salt Project Repository
baseurl=https://packages.broadcom.com/artifactory/saltproject-rpm/rhel/${el_version}/x86_64/${SALT_VERSION}/
enabled=1
gpgcheck=${GPGCHECK:-1}
gpgkey=https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public
EOF

    log "Repository configuration created successfully"
    
    # Clean and rebuild cache
    $pkg_mgr clean all
    if ! $pkg_mgr makecache; then
        warn "Failed to build cache, but continuing..."
    fi
    
    return 0
}

setup_rpm_repo() {
    local pkg_mgr="$1"
    local el_version
    el_version=$(get_el_version)
    
    log "Setting up Salt repository for RHEL/Fedora (EL${el_version})..."
    
    # Clean up old repos
    rpm -e --nodeps salt-repo 2>/dev/null || true
    rm -f /etc/yum.repos.d/salt*.repo
    
    # Option 3: Verify repository access first
    if ! verify_repo_access "$el_version"; then
        error "Cannot access Salt repository. Check network connectivity and firewall rules."
        die "Repository verification failed. Aborting installation."
    fi
    
    # Option 2: Try repo RPM first, fallback to direct configuration
    if verify_repo_rpm_exists "$el_version"; then
        log "Repository RPM is available, attempting installation..."
        if setup_rpm_repo_via_rpm "$pkg_mgr" "$el_version"; then
            log "Repository configured via RPM package"
            return 0
        else
            warn "RPM installation failed, falling back to direct configuration..."
        fi
    else
        warn "Repository RPM not available, using direct configuration..."
    fi
    
    # Fallback: Direct repository configuration
    if setup_rpm_repo_direct "$pkg_mgr" "$el_version"; then
        log "Repository configured via direct method"
        return 0
    else
        die "Failed to configure repository using all available methods"
    fi
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
    esac
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

copy_tools() {
    local tools_path="$1"
    
    if [[ -z "$tools_path" ]]; then
        debug "No tools path specified, skipping tools copy"
        return 0
    fi
    
    if [[ ! -d "$tools_path" ]]; then
        warn "Tools directory not found: $tools_path"
        return 0
    fi
    
    log "Copying tools from $tools_path to /etc/runtl..."
    mkdir -p /etc/runtl
    cp -r "$tools_path"/* /etc/runtl/
    chmod -R 750 /etc/runtl
}

# --- Parse Arguments ---
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -m, --master IP     Salt Master IP address (default: $DEFAULT_MASTER_IP)
    -i, --id ID         Minion ID (default: system hostname)
    -t, --tools PATH    Path to tools directory to copy to /etc/runtl
    -d, --debug         Enable debug output
    -h, --help          Show this help message

Examples:
    $0                                    # Interactive mode
    $0 -m 10.0.0.1 -i webserver01        # Non-interactive
    $0 -m 10.0.0.1 -t /opt/tools         # With tools copy
EOF
    exit 0
}

SALT_MASTER_IP=""
MINION_ID=""
TOOLS_PATH=""
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
        -t|--tools)
            TOOLS_PATH="$2"
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
    echo "# Salt Minion Installer - Option 2+3                #"
    echo "# Fallback Logic with Repository Verification      #"
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
        if [[ "$INTERACTIVE" == "true" ]]; then
            read -rp "Enter Minion ID [Default: $(hostname -f)]: " MINION_ID
        fi
        MINION_ID="${MINION_ID:-$(hostname -f)}"
    fi
    log "Minion ID: $MINION_ID"
    
    # Check for existing installation
    if systemctl is-active --quiet salt-minion; then
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
    esac
    
    # Install minion
    install_salt_minion "$pkg_mgr"
    
    # Configure minion
    configure_minion "$SALT_MASTER_IP" "$MINION_ID"
    
    # Copy tools if specified
    copy_tools "$TOOLS_PATH"
    
    # Start service
    start_minion_service
    
    # Summary
    echo
    echo "#####################################################"
    echo "# MINION SETUP COMPLETE                             #"
    echo "#####################################################"
    echo "Minion ID:  $MINION_ID"
    echo "Master IP:  $SALT_MASTER_IP"
    echo "Crypto:     SHA-1 Permitted"
    echo "Status:     $(systemctl is-active salt-minion 2>/dev/null || echo 'unknown')"
    echo "#####################################################"
    echo
    echo "Next step: Accept the key on the master with:"
    echo "  salt-key -a '$MINION_ID'"
    echo
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo "Debug logs available at:"
        echo "  - /tmp/salt-repo-install.log (if repo RPM was attempted)"
        echo "  - journalctl -u salt-minion (for service logs)"
    fi
}

main "$@"
