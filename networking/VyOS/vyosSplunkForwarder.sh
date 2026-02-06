#!/bin/bash
#===============================================================================
#
#  ██╗   ██╗██╗   ██╗ ██████╗ ███████╗    ███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗
#  ██║   ██║╚██╗ ██╔╝██╔═══██╗██╔════╝    ██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝
#  ██║   ██║ ╚████╔╝ ██║   ██║███████╗    ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝
#  ╚██╗ ██╔╝  ╚██╔╝  ██║   ██║╚════██║    ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗
#   ╚████╔╝    ██║   ╚██████╔╝███████║    ███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ██╗
#    ╚═══╝     ╚═╝    ╚═════╝ ╚══════╝    ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
#
#  VyOS Splunk Universal Forwarder Installation Script
#  Version: 1.0.0
#
#  Installs Splunk Universal Forwarder on VyOS with:
#    - Temporary Debian repository configuration for dependencies
#    - VyOS-specific log monitoring (system, firewall, VPN)
#    - Zeek log integration (if installed)
#    - Proper cleanup of build repositories
#
#  Usage: ./vyosSplunkForwarder.sh [indexer_ip] [username] [password]
#
#  Supported VyOS Versions:
#    - VyOS 1.4.x (sagitta) - Debian 12 (Bookworm) based
#    - VyOS 1.3.x (equuleus) - Debian 11 (Bullseye) based
#    - VyOS 1.5.x (circinus) - Debian 12 based
#
#  Based on splunkForwarderLinuxGeneral.sh by Samuel Brucker
#  Adapted for VyOS compatibility
#
#===============================================================================

set -euo pipefail

# Save original arguments for sudo hint
ORIGINAL_ARGS=("$@")

# Define Splunk Forwarder variables
SPLUNK_VERSION="10.0.2"
SPLUNK_BUILD="e2d18b4767e9"
SPLUNK_PACKAGE_TGZ="splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE_TGZ}"
INSTALL_DIR="/opt/splunkforwarder"

# VyOS detection
VYOS_VERSION=""
DEBIAN_CODENAME=""

# Zeek detection
ZEEK_DIR=""
ZEEK_INSTALLED=false

# Set defaults for configuration
DEFAULT_INDEXER_IP="192.168.56.13"
DEFAULT_ADMIN_USERNAME="admin"

# Override defaults with command-line arguments if they are provided
INDEXER_IP=${1:-$DEFAULT_INDEXER_IP}
ADMIN_USERNAME=${2:-$DEFAULT_ADMIN_USERNAME}
ADMIN_PASSWORD=${3:-}

# Pretty colors :)
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
fi

log_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP $1]${NC} $2"; }

# Ensure terminal echo is restored on exit/interrupt
cleanup() {
    stty echo 2>/dev/null || true
    # Remove temporary Debian repos if they exist
    if [[ -f /etc/apt/sources.list.d/debian-splunk-build.list ]]; then
        rm -f /etc/apt/sources.list.d/debian-splunk-build.list 2>/dev/null || true
        apt-get update -qq 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        if [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]]; then
            log_info "Try: sudo $0 ${ORIGINAL_ARGS[*]}"
        else
            log_info "Try: sudo $0"
        fi
        exit 1
    fi
}

detect_vyos() {
    log_header "Detecting VyOS Environment"

    if [[ ! -f /etc/vyos-release ]] && [[ ! -d /opt/vyatta ]]; then
        log_error "This doesn't appear to be a VyOS system"
        log_info "For other Linux systems, use splunkForwarderLinuxGeneral.sh"
        exit 1
    fi

    # Get VyOS version
    if [[ -f /etc/vyos-release ]]; then
        VYOS_VERSION=$(grep -oP 'version="\K[^"]+' /etc/vyos-release 2>/dev/null || echo "unknown")
    elif [[ -f /opt/vyatta/etc/version ]]; then
        VYOS_VERSION=$(cat /opt/vyatta/etc/version 2>/dev/null || echo "unknown")
    fi
    log_success "VyOS version: $VYOS_VERSION"

    # Detect Debian base version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DEBIAN_CODENAME="${VERSION_CODENAME:-}"
    fi

    if [[ -z "$DEBIAN_CODENAME" ]] && [[ -f /etc/debian_version ]]; then
        local deb_ver
        deb_ver=$(cat /etc/debian_version)
        case "$deb_ver" in
            12*|bookworm*) DEBIAN_CODENAME="bookworm" ;;
            11*|bullseye*) DEBIAN_CODENAME="bullseye" ;;
            *) DEBIAN_CODENAME="bookworm" ;;
        esac
    fi

    log_success "Debian base: $DEBIAN_CODENAME"
}

detect_zeek() {
    log_info "Checking for Zeek installation..."

    local zeek_paths=("/opt/zeek" "/usr/local/zeek")

    for path in "${zeek_paths[@]}"; do
        if [[ -d "$path" && -f "$path/bin/zeek" ]]; then
            ZEEK_DIR="$path"
            ZEEK_INSTALLED=true
            log_success "Found Zeek at: $ZEEK_DIR"
            return 0
        fi
    done

    log_info "Zeek not found - Zeek log monitors will be skipped"
    return 0
}

setup_debian_repos() {
    log_header "Configuring Debian Repositories"
    log_warning "VyOS limits package installation - enabling Debian repos temporarily"

    # Backup existing sources.list if it exists
    [[ -f /etc/apt/sources.list ]] && cp /etc/apt/sources.list "/etc/apt/sources.list.backup.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    cat > /etc/apt/sources.list.d/debian-splunk-build.list << EOF
deb http://deb.debian.org/debian ${DEBIAN_CODENAME} main contrib
deb http://deb.debian.org/debian ${DEBIAN_CODENAME}-updates main contrib
EOF
    log_success "Created Debian repository config"

    apt-get update -qq 2>&1 | grep -v "^W:" || true
    log_success "Repository configuration complete"
}

cleanup_repos() {
    log_info "Removing temporary Debian repositories..."
    rm -f /etc/apt/sources.list.d/debian-splunk-build.list
    apt-get update -qq 2>/dev/null || true
    log_success "Removed build repositories"
}

install_dependencies() {
    log_header "Installing Dependencies"

    # Required commands - wget and tar are essential, setfacl is optional
    local required_cmds=("wget" "tar")
    local optional_cmds=("setfacl")
    local all_deps_installed=true

    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_info "Installing $cmd..."
            local package_name=""
            case "$cmd" in
                wget) package_name="wget" ;;
                tar) package_name="tar" ;;
            esac

            if [[ -n "$package_name" ]]; then
                if ! apt-get install -y -qq "$package_name" 2>/dev/null; then
                    log_error "Failed to install $package_name"
                    all_deps_installed=false
                else
                    log_success "Installed $cmd"
                fi
            fi
        else
            log_success "$cmd already installed"
        fi
    done

    # Try to install optional dependencies but don't fail if they're unavailable
    for cmd in "${optional_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_info "Attempting to install optional dependency: $cmd..."
            case "$cmd" in
                setfacl)
                    if apt-get install -y -qq acl 2>/dev/null; then
                        log_success "Installed $cmd (optional)"
                    else
                        log_warning "$cmd not available - will use chmod fallback"
                    fi
                    ;;
            esac
        else
            log_success "$cmd already installed (optional)"
        fi
    done

    if [[ "$all_deps_installed" == false ]]; then
        log_error "Required dependencies could not be installed"
        exit 1
    fi

    log_success "All required dependencies satisfied"
}

prompt_password() {
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        echo -e "${BLUE}Enter password for Splunk admin user:${NC}"
        while true; do
            echo -n "Password: "
            stty -echo
            read -r pass1
            stty echo
            echo
            echo -n "Confirm password: "
            stty -echo
            read -r pass2
            stty echo
            echo
            if [[ "$pass1" == "$pass2" ]]; then
                ADMIN_PASSWORD="$pass1"
                break
            else
                echo -e "${RED}Passwords do not match. Please try again.${NC}"
            fi
        done
    fi
}

create_splunk_user() {
    if ! id -u splunk &>/dev/null; then
        log_info "Creating splunk user and group..."
        groupadd splunk 2>/dev/null || true
        useradd -r -g splunk -d "$INSTALL_DIR" splunk 2>/dev/null || true
        log_success "Created splunk user"
    else
        log_success "Splunk user already exists"
    fi
}

install_splunk() {
    log_header "Installing Splunk Universal Forwarder"

    # IDEMPOTENCY CHECK
    if [[ -d "$INSTALL_DIR" ]]; then
        log_warning "Splunk Universal Forwarder already installed at $INSTALL_DIR"
        log_info "Remove $INSTALL_DIR to reinstall"
        exit 0
    fi

    local max_retries=3
    local retry_count=0
    local download_success=false
    local download_path="/tmp/$SPLUNK_PACKAGE_TGZ"

    log_info "Downloading Splunk Forwarder v$SPLUNK_VERSION..."

    while [[ $retry_count -lt $max_retries ]] && [[ $download_success == false ]]; do
        local status=0
        if [[ $retry_count -eq 0 ]]; then
            wget -q --show-progress -O "$download_path" "$SPLUNK_DOWNLOAD_URL" || status=$?
        else
            log_warning "Retrying without certificate verification..."
            wget -q --show-progress --no-check-certificate -O "$download_path" "$SPLUNK_DOWNLOAD_URL" || status=$?
        fi

        if [[ $status -eq 0 ]]; then
            download_success=true
        else
            retry_count=$((retry_count + 1))
            log_warning "Download failed (attempt $retry_count/$max_retries)"
            sleep 5
        fi
    done

    if [[ $download_success == false ]]; then
        log_error "All download attempts failed"
        exit 1
    fi

    log_info "Extracting Splunk Forwarder..."
    tar -xzf "$download_path" -C /opt
    rm -f "$download_path"

    create_splunk_user
    chown -R splunk:splunk "$INSTALL_DIR"

    log_success "Splunk Forwarder installed to $INSTALL_DIR"
}

set_admin_credentials() {
    log_info "Setting admin credentials..."
    local user_seed_file="$INSTALL_DIR/etc/system/local/user-seed.conf"

    cat > "$user_seed_file" << EOF
[user_info]
USERNAME = $ADMIN_USERNAME
PASSWORD = $ADMIN_PASSWORD
EOF

    chown splunk:splunk "$user_seed_file"
    log_success "Admin credentials configured"
}

setup_monitors() {
    log_header "Configuring VyOS Log Monitors"

    local monitor_config="$INSTALL_DIR/etc/system/local/inputs.conf"

    cat > "$monitor_config" << 'MONITORS_EOF'
# =============================================================================
# VyOS Splunk Universal Forwarder - Log Monitors
# =============================================================================
# This configuration is optimized for VyOS routers/firewalls
# Splunk will gracefully ignore paths that don't exist
# =============================================================================

# -----------------------------------------------------------------------------
# VyOS System Logs (index = linux)
# -----------------------------------------------------------------------------

[monitor:///var/log/messages]
index = linux
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/auth.log]
index = linux
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/syslog]
index = linux
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/kern.log]
index = linux
sourcetype = linux_kernel
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$


# -----------------------------------------------------------------------------
# VyOS Configuration & Commit Logs
# -----------------------------------------------------------------------------

# VyOS configuration changes and commits
[monitor:///var/log/vyatta/*]
index = network
sourcetype = vyos:config
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# Boot configuration (monitor for unauthorized changes)
[monitor:///config/config.boot]
index = network
sourcetype = vyos:config_boot
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# VyOS Services
# -----------------------------------------------------------------------------

# DHCP Server logs
[monitor:///var/log/dhcpd.log]
index = network
sourcetype = dhcpd
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# DNS (if running local DNS)
[monitor:///var/log/pdns.log]
index = network
sourcetype = powerdns
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# NTP
[monitor:///var/log/ntpd.log]
index = network
sourcetype = ntp
crcSalt = <SOURCE>


# -----------------------------------------------------------------------------
# VPN Logs
# -----------------------------------------------------------------------------

# OpenVPN
[monitor:///var/log/openvpn*.log]
index = network
sourcetype = openvpn
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# IPsec/StrongSwan
[monitor:///var/log/charon.log]
index = network
sourcetype = ipsec:charon
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# WireGuard (logs go to syslog/messages typically)


# -----------------------------------------------------------------------------
# Firewall Logs (if logging enabled in VyOS firewall rules)
# -----------------------------------------------------------------------------

# VyOS firewall logs typically go to /var/log/messages with kern facility
# Use the messages monitor above, or enable dedicated firewall logging:

# If using rsyslog to separate firewall logs:
[monitor:///var/log/firewall.log]
index = network
sourcetype = vyos:firewall
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$


# -----------------------------------------------------------------------------
# Routing Protocol Logs
# -----------------------------------------------------------------------------

# FRRouting (BGP, OSPF, etc.)
[monitor:///var/log/frr/*.log]
index = network
sourcetype = frr
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# Quagga (older VyOS versions)
[monitor:///var/log/quagga/*.log]
index = network
sourcetype = quagga
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

MONITORS_EOF

    # Zeek monitors - always included; Splunk ignores paths that don't exist
    cat >> "$monitor_config" << 'ZEEK_MONITORS_EOF'

# -----------------------------------------------------------------------------
# Zeek Network Security Monitor Logs
# -----------------------------------------------------------------------------
# Splunk gracefully ignores monitor paths that do not exist.

# Connection logs - all network connections
[monitor:///opt/zeek/logs/current/conn.log]
index = network
sourcetype = zeek:conn
crcSalt = <SOURCE>

# DNS logs - all DNS queries and responses
[monitor:///opt/zeek/logs/current/dns.log]
index = network
sourcetype = zeek:dns
crcSalt = <SOURCE>

# HTTP logs - HTTP requests (unencrypted only)
[monitor:///opt/zeek/logs/current/http.log]
index = network
sourcetype = zeek:http
crcSalt = <SOURCE>

# Notice log - ALERTS from detection scripts (C2, malware, attacks)
[monitor:///opt/zeek/logs/current/notice.log]
index = network
sourcetype = zeek:notice
crcSalt = <SOURCE>

# SSL/TLS logs - certificate and handshake info
[monitor:///opt/zeek/logs/current/ssl.log]
index = network
sourcetype = zeek:ssl
crcSalt = <SOURCE>

# SSH logs - SSH connection details and auth
[monitor:///opt/zeek/logs/current/ssh.log]
index = network
sourcetype = zeek:ssh
crcSalt = <SOURCE>

# DCE/RPC logs - Windows RPC traffic (lateral movement indicator)
[monitor:///opt/zeek/logs/current/dce_rpc.log]
index = network
sourcetype = zeek:dce_rpc
crcSalt = <SOURCE>

# SMB file access logs
[monitor:///opt/zeek/logs/current/smb_mapping.log]
index = network
sourcetype = zeek:smb_mapping
crcSalt = <SOURCE>

[monitor:///opt/zeek/logs/current/smb_files.log]
index = network
sourcetype = zeek:smb_files
crcSalt = <SOURCE>

# Kerberos logs - authentication and ticket requests
[monitor:///opt/zeek/logs/current/kerberos.log]
index = network
sourcetype = zeek:kerberos
crcSalt = <SOURCE>

# File analysis logs
[monitor:///opt/zeek/logs/current/files.log]
index = network
sourcetype = zeek:files
crcSalt = <SOURCE>

# X.509 certificate logs
[monitor:///opt/zeek/logs/current/x509.log]
index = network
sourcetype = zeek:x509
crcSalt = <SOURCE>

ZEEK_MONITORS_EOF

    # Add test log monitor
    cat >> "$monitor_config" << 'EOF'

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor:///tmp/test.log]
index = network
sourcetype = test
crcSalt = <SOURCE>

EOF

    chown splunk:splunk "$monitor_config"
    log_success "Monitor configuration complete"
}

configure_forwarder() {
    log_info "Configuring forwarder to send logs to $INDEXER_IP:9997..."
    "$INSTALL_DIR/bin/splunk" add forward-server "$INDEXER_IP:9997" -auth "$ADMIN_USERNAME:$ADMIN_PASSWORD"
    log_success "Forward-server configured"
}

start_splunk() {
    log_header "Starting Splunk Universal Forwarder"

    log_info "Starting Splunk and accepting license..."
    "$INSTALL_DIR/bin/splunk" start --accept-license --answer-yes --no-prompt

    log_info "Enabling boot-start..."
    "$INSTALL_DIR/bin/splunk" enable boot-start 2>/dev/null || log_warning "boot-start may already be configured"

    log_success "Splunk Forwarder started"
}

restart_splunk() {
    log_info "Restarting Splunk Forwarder..."
    if systemctl restart SplunkForwarder 2>/dev/null; then
        log_success "Splunk Forwarder restarted via systemd"
    elif "$INSTALL_DIR/bin/splunk" restart; then
        log_success "Splunk Forwarder restarted"
    else
        log_error "Failed to restart Splunk Forwarder"
        return 1
    fi
}

create_test_log() {
    log_info "Creating test log entry..."
    echo "VyOS Splunk Forwarder test entry - $(date)" > /tmp/test.log

    # Try setfacl first, fall back to chmod
    if command -v setfacl &> /dev/null; then
        setfacl -m u:splunk:r /tmp/test.log 2>/dev/null || chmod 644 /tmp/test.log
    else
        chmod 644 /tmp/test.log
    fi

    log_success "Test log created at /tmp/test.log"
}

verify_installation() {
    log_header "Verifying Installation"

    if [[ -x "$INSTALL_DIR/bin/splunk" ]]; then
        local version
        version=$("$INSTALL_DIR/bin/splunk" version 2>/dev/null) || version="unknown"
        log_success "Splunk version: $version"
    else
        log_error "Splunk binary not found"
        return 1
    fi

    if systemctl is-active --quiet SplunkForwarder 2>/dev/null; then
        log_success "SplunkForwarder service is running"
    elif pgrep -f splunkd &>/dev/null; then
        log_success "splunkd process is running"
    else
        log_warning "Splunk may not be running"
    fi

    log_success "Installation verified"
}

print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     VYOS SPLUNK FORWARDER INSTALLATION COMPLETE                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Installation Summary:${NC}"
    echo "  VyOS Version:     $VYOS_VERSION"
    echo "  Splunk Version:   $SPLUNK_VERSION"
    echo "  Install Path:     $INSTALL_DIR"
    echo "  Indexer:          $INDEXER_IP:9997"
    echo ""
    echo -e "${GREEN}Monitored Log Categories:${NC}"
    echo "  index=linux:"
    echo "    - System logs (/var/log/messages, auth.log, syslog, kern.log)"
    echo "  index=network:"
    echo "    - VyOS configuration changes (/var/log/vyatta/*, config.boot)"
    echo "    - VPN logs (OpenVPN, IPsec/StrongSwan)"
    echo "    - Routing protocols (FRR/Quagga)"
    echo "    - Firewall, DHCP, DNS services"
    echo "    - Zeek logs (conn, dns, http, notice, ssl, ssh, dce_rpc, smb, kerberos, files, x509)"
    echo ""
    echo -e "${GREEN}Management Commands:${NC}"
    echo "  systemctl status SplunkForwarder"
    echo "  $INSTALL_DIR/bin/splunk status"
    echo "  $INSTALL_DIR/bin/splunk list forward-server"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Verify logs appear in Splunk (index=linux for system, index=network for network)"
    echo "  2. Check forwarder status: $INSTALL_DIR/bin/splunk list forward-server"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     VYOS SPLUNK UNIVERSAL FORWARDER INSTALLER v1.0.0           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Pre-flight checks
    check_root

    log_step "1/10" "Detecting VyOS"
    detect_vyos
    detect_zeek

    log_step "2/10" "Configuring Repositories"
    setup_debian_repos

    log_step "3/10" "Installing Dependencies"
    install_dependencies

    log_step "4/10" "Prompting for Credentials"
    prompt_password

    # Display configuration
    echo ""
    echo -e "${BLUE}--- Configuration ---${NC}"
    echo -e "  Indexer IP:     ${GREEN}$INDEXER_IP${NC}"
    echo -e "  Admin Username: ${GREEN}$ADMIN_USERNAME${NC}"
    echo -e "  Admin Password: ${GREEN}(hidden)${NC}"
    echo -e "${BLUE}---------------------${NC}"
    echo ""

    log_step "5/10" "Installing Splunk Forwarder"
    install_splunk

    log_step "6/10" "Setting Credentials"
    set_admin_credentials

    log_step "7/10" "Starting Splunk"
    start_splunk

    log_step "8/10" "Configuring Monitors"
    setup_monitors

    log_step "9/10" "Configuring Forwarder"
    configure_forwarder

    # Cleanup repos before restart
    cleanup_repos

    # Restart to apply monitor config
    restart_splunk

    log_step "10/10" "Verifying Installation"
    create_test_log
    verify_installation

    print_summary
}

main "$@"
