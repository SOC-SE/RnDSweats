#!/bin/bash
#
# SSH Installation and Hardening Script
# Installs and configures SSH with security best practices
#
# Supports: Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Oracle Linux, Alpine
#
# Usage: sudo ./ssh_harden.sh [OPTIONS]
#   Options:
#     --install-only    Only install SSH, skip hardening
#     --harden-only     Only harden existing SSH (don't install)
#     --port PORT       Change SSH port (default: 22)
#     --allow-root      Allow root login (not recommended)
#     -h, --help        Show this help
#
set -euo pipefail

# --- CONFIGURATION ---
SSH_PORT=22
ALLOW_ROOT=false
INSTALL_SSH=true
HARDEN_SSH=true

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- ARGUMENT PARSING ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-only)
            HARDEN_SSH=false
            shift
            ;;
        --harden-only)
            INSTALL_SSH=false
            shift
            ;;
        --port)
            SSH_PORT="$2"
            shift 2
            ;;
        --allow-root)
            ALLOW_ROOT=true
            shift
            ;;
        -h|--help)
            echo "SSH Installation and Hardening Script"
            echo ""
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --install-only    Only install SSH, skip hardening"
            echo "  --harden-only     Only harden existing SSH (don't install)"
            echo "  --port PORT       Change SSH port (default: 22)"
            echo "  --allow-root      Allow root login (not recommended)"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# --- VALIDATE PORT ---
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
    log_error "Invalid port number: $SSH_PORT (must be 1-65535)"
    exit 1
fi

# --- DETECT SYSTEM ---
detect_system() {
    # shellcheck disable=SC2034  # SSH_PKG kept for reference/future use
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        SSH_PKG="openssh-server"
        SSH_SERVICE="ssh"
        SSHD_CONFIG="/etc/ssh/sshd_config"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        SSH_PKG="openssh-server"
        SSH_SERVICE="sshd"
        SSHD_CONFIG="/etc/ssh/sshd_config"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        SSH_PKG="openssh-server"
        SSH_SERVICE="sshd"
        SSHD_CONFIG="/etc/ssh/sshd_config"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
        SSH_PKG="openssh"
        SSH_SERVICE="sshd"
        SSHD_CONFIG="/etc/ssh/sshd_config"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        SSH_PKG="openssh"
        SSH_SERVICE="sshd"
        SSHD_CONFIG="/etc/ssh/sshd_config"
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    # Detect init system
    if command -v systemctl &>/dev/null; then
        # Use systemctl even in containers (it can manage services without full systemd)
        INIT_SYSTEM="systemd"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    elif command -v service &>/dev/null; then
        INIT_SYSTEM="sysvinit"
    else
        # Fallback - try to start service directly
        INIT_SYSTEM="direct"
    fi

    log_info "Detected: PKG_MGR=$PKG_MGR, INIT=$INIT_SYSTEM, SERVICE=$SSH_SERVICE"
}

# --- INSTALL SSH ---
install_ssh() {
    log_info "Installing SSH server..."

    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq openssh-server
            ;;
        dnf)
            dnf install -y -q openssh-server
            ;;
        yum)
            yum install -y -q openssh-server
            ;;
        apk)
            apk add --quiet openssh
            ;;
        pacman)
            pacman -S --noconfirm --quiet openssh
            ;;
    esac

    # Generate host keys if they don't exist (needed in containers and fresh installs)
    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        log_info "Generating SSH host keys..."
        ssh-keygen -A
    fi

    log_info "SSH server installed"
}

# --- START SSH SERVICE ---
start_ssh() {
    log_info "Starting and enabling SSH service..."

    case "$INIT_SYSTEM" in
        systemd)
            systemctl enable "$SSH_SERVICE" 2>/dev/null || true
            systemctl start "$SSH_SERVICE" 2>/dev/null || {
                # In containers, systemctl may fail - try direct start
                log_warn "systemctl failed, trying direct start..."
                /usr/sbin/sshd 2>/dev/null || /usr/bin/sshd 2>/dev/null || true
            }
            ;;
        openrc)
            rc-update add "$SSH_SERVICE" default 2>/dev/null || true
            rc-service "$SSH_SERVICE" start
            ;;
        sysvinit)
            service "$SSH_SERVICE" start
            update-rc.d "$SSH_SERVICE" defaults 2>/dev/null || chkconfig "$SSH_SERVICE" on 2>/dev/null || true
            ;;
        direct)
            # Direct sshd start (containers without init system)
            /usr/sbin/sshd 2>/dev/null || /usr/bin/sshd 2>/dev/null || {
                log_error "Could not start sshd directly"
                return 1
            }
            ;;
    esac

    log_info "SSH service started"
}

# --- HARDEN SSH ---
harden_ssh() {
    log_info "Hardening SSH configuration..."

    if [[ ! -f "$SSHD_CONFIG" ]]; then
        log_error "SSH config not found: $SSHD_CONFIG"
        exit 1
    fi

    # Backup original config
    local backup
    backup="${SSHD_CONFIG}.bak.$(date +%s)"
    cp "$SSHD_CONFIG" "$backup"
    log_info "Backed up config to: $backup"

    # Determine root login setting
    local root_login="no"
    if [[ "$ALLOW_ROOT" == "true" ]]; then
        root_login="prohibit-password"
        log_warn "Root login enabled (key-only)"
    fi

    # Create hardened config
    cat > "$SSHD_CONFIG" << EOF
# SSH Hardened Configuration
# Generated by CCDC Toolkit - $(date)
# Original backed up to: $backup

# Network
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0

# Protocol
Protocol 2

# Host Keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin $root_login
MaxAuthTries 3
MaxSessions 10
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# Disable dangerous features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no

# Timeouts
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
UseDNS no
DebianBanner no

# Banner
Banner /etc/issue.net

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Ciphers and MACs (strong only)
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
EOF

    # Fix sftp path for different distros
    if [[ -f /usr/libexec/openssh/sftp-server ]]; then
        sed -i 's|/usr/lib/openssh/sftp-server|/usr/libexec/openssh/sftp-server|' "$SSHD_CONFIG"
    elif [[ -f /usr/lib/ssh/sftp-server ]]; then
        sed -i 's|/usr/lib/openssh/sftp-server|/usr/lib/ssh/sftp-server|' "$SSHD_CONFIG"
    fi

    # Create banner if it doesn't exist
    if [[ ! -f /etc/issue.net ]]; then
        echo "Unauthorized access prohibited. All activity is monitored." > /etc/issue.net
    fi

    log_info "SSH hardening applied"
}

# --- VALIDATE CONFIG ---
validate_config() {
    log_info "Validating SSH configuration..."

    if sshd -t 2>/dev/null; then
        log_info "Configuration is valid"
        return 0
    else
        log_error "Configuration validation failed!"
        sshd -t
        return 1
    fi
}

# --- RESTART SSH ---
restart_ssh() {
    log_info "Restarting SSH service..."

    case "$INIT_SYSTEM" in
        systemd)
            systemctl restart "$SSH_SERVICE" 2>/dev/null || {
                # In containers, try killing and restarting directly
                pkill -x sshd 2>/dev/null || true
                sleep 1
                /usr/sbin/sshd 2>/dev/null || /usr/bin/sshd 2>/dev/null || true
            }
            ;;
        openrc)
            rc-service "$SSH_SERVICE" restart
            ;;
        sysvinit)
            service "$SSH_SERVICE" restart
            ;;
        direct)
            pkill -x sshd 2>/dev/null || true
            sleep 1
            /usr/sbin/sshd 2>/dev/null || /usr/bin/sshd 2>/dev/null || {
                log_error "Could not restart sshd"
                return 1
            }
            ;;
    esac

    log_info "SSH service restarted"
}

# --- SHOW STATUS ---
show_status() {
    echo ""
    echo "=== SSH Status ==="

    case "$INIT_SYSTEM" in
        systemd)
            systemctl is-active "$SSH_SERVICE" 2>/dev/null && echo "Service: RUNNING" || {
                # Check if sshd process is running (fallback for containers)
                if command -v pgrep &>/dev/null; then
                    pgrep -x sshd >/dev/null && echo "Service: RUNNING (direct)" || echo "Service: STOPPED"
                else
                    ps aux 2>/dev/null | grep -v grep | grep -q '[s]shd' && echo "Service: RUNNING (direct)" || echo "Service: STOPPED"
                fi
            }
            ;;
        openrc)
            rc-service "$SSH_SERVICE" status && echo "Service: RUNNING" || echo "Service: STOPPED"
            ;;
        sysvinit)
            service "$SSH_SERVICE" status && echo "Service: RUNNING" || echo "Service: STOPPED"
            ;;
        direct)
            # Try pgrep first, fallback to ps
            if command -v pgrep &>/dev/null; then
                pgrep -x sshd >/dev/null && echo "Service: RUNNING (direct)" || echo "Service: STOPPED"
            else
                ps aux 2>/dev/null | grep -v grep | grep -q '[s]shd' && echo "Service: RUNNING (direct)" || echo "Service: STOPPED"
            fi
            ;;
    esac

    echo ""
    echo "Listening on:"
    ss -tlnp 2>/dev/null | grep -E ":${SSH_PORT}\b" || netstat -tlnp 2>/dev/null | grep -E ":${SSH_PORT}\b" || echo "  Unable to determine"

    echo ""
    echo "Configuration highlights:"
    grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" "$SSHD_CONFIG" 2>/dev/null | sed 's/^/  /'
}

# --- MAIN ---
detect_system

if [[ "$INSTALL_SSH" == "true" ]]; then
    install_ssh
    start_ssh
fi

if [[ "$HARDEN_SSH" == "true" ]]; then
    harden_ssh
    if validate_config; then
        restart_ssh
    else
        log_error "Restoring backup due to invalid config"
        # Find most recent backup
        latest_backup=$(find "$(dirname "$SSHD_CONFIG")" -name "sshd_config.bak.*" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
        if [[ -n "$latest_backup" ]]; then
            cp "$latest_backup" "$SSHD_CONFIG"
            log_info "Restored: $latest_backup"
        fi
        exit 1
    fi
fi

show_status

log_info "SSH setup complete"
if [[ "$SSH_PORT" != "22" ]]; then
    log_warn "SSH is running on non-standard port: $SSH_PORT"
    log_warn "Connect with: ssh -p $SSH_PORT user@host"
fi
