#!/bin/bash
# ==============================================================================
# Script Name: systemBackups.sh
# Description: Quick backup of critical system files for disaster recovery
#              and forensic comparison. Run FIRST on any new system access.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./systemBackups.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -o, --output     Backup directory (default: /root/system_backup_TIMESTAMP)
#   -q, --quiet      Minimal output
#   -c, --compress   Create compressed archive after backup
#   -e, --encrypt    Encrypt backup with password (requires gpg)
#
# What Gets Backed Up:
#   - Authentication: /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
#   - PAM: /etc/pam.d/*
#   - SSH: /etc/ssh/*, ~/.ssh/authorized_keys
#   - Shell profiles: /etc/profile, /etc/bashrc, ~/.bashrc, ~/.profile
#   - Cron: /etc/crontab, /etc/cron.d/*, user crontabs
#   - Firewall: iptables, nftables, firewalld, ufw rules
#   - System: /etc/hosts, /etc/resolv.conf, /etc/fstab
#   - Services: systemd service files
#   - Network: Network baseline (listeners, connections)
#   - Process: Process baseline
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   3 - Permission denied
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
OUTPUT_DIR="/root/system_backup_${TIMESTAMP}"
QUIET=false
COMPRESS=false
ENCRYPT=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 3
    fi
}

# Backup a file or directory with error handling
backup_item() {
    local src="$1"
    local dest_dir="$2"
    local dest_name="${3:-$(basename "$src")}"

    if [[ -e "$src" ]]; then
        if [[ -d "$src" ]]; then
            cp -a "$src" "$dest_dir/$dest_name" 2>/dev/null && \
                log "Backed up directory: $src" || \
                warn "Failed to backup: $src"
        else
            cp -a "$src" "$dest_dir/$dest_name" 2>/dev/null && \
                log "Backed up: $src" || \
                warn "Failed to backup: $src"
        fi
    else
        [[ "$QUIET" == "false" ]] && echo "  [SKIP] $src (not found)"
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -c|--compress)
            COMPRESS=true
            shift
            ;;
        -e|--encrypt)
            ENCRYPT=true
            COMPRESS=true  # Encryption requires compression first
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---
check_root

echo "========================================"
echo "SYSTEM BACKUP - $HOSTNAME"
echo "Time: $(date)"
echo "========================================"
echo ""

# Create backup directory structure
log "Creating backup directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"/{auth,pam,ssh,profiles,cron,firewall,system,services,baseline}
chmod 700 "$OUTPUT_DIR"

# ==============================================================================
# AUTHENTICATION FILES
# ==============================================================================
log "Backing up authentication files..."
backup_item /etc/passwd "$OUTPUT_DIR/auth"
backup_item /etc/shadow "$OUTPUT_DIR/auth"
backup_item /etc/group "$OUTPUT_DIR/auth"
backup_item /etc/gshadow "$OUTPUT_DIR/auth"
backup_item /etc/sudoers "$OUTPUT_DIR/auth"
if [[ -d /etc/sudoers.d ]]; then
    backup_item /etc/sudoers.d "$OUTPUT_DIR/auth"
fi

# ==============================================================================
# PAM CONFIGURATION
# ==============================================================================
log "Backing up PAM configuration..."
if [[ -d /etc/pam.d ]]; then
    backup_item /etc/pam.d "$OUTPUT_DIR/pam"
fi
backup_item /etc/security/limits.conf "$OUTPUT_DIR/pam" 2>/dev/null
backup_item /etc/security/access.conf "$OUTPUT_DIR/pam" 2>/dev/null

# ==============================================================================
# SSH CONFIGURATION
# ==============================================================================
log "Backing up SSH configuration..."
if [[ -d /etc/ssh ]]; then
    backup_item /etc/ssh "$OUTPUT_DIR/ssh"
fi

# Backup all authorized_keys files
mkdir -p "$OUTPUT_DIR/ssh/authorized_keys"
find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
    user=$(echo "$keyfile" | cut -d'/' -f3)
    cp "$keyfile" "$OUTPUT_DIR/ssh/authorized_keys/${user}_authorized_keys" 2>/dev/null
done
if [[ -f /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys "$OUTPUT_DIR/ssh/authorized_keys/root_authorized_keys" 2>/dev/null
fi

# ==============================================================================
# SHELL PROFILES
# ==============================================================================
log "Backing up shell profiles..."
backup_item /etc/profile "$OUTPUT_DIR/profiles"
backup_item /etc/profile.d "$OUTPUT_DIR/profiles" 2>/dev/null
backup_item /etc/bashrc "$OUTPUT_DIR/profiles" 2>/dev/null
backup_item /etc/bash.bashrc "$OUTPUT_DIR/profiles" 2>/dev/null
backup_item /etc/environment "$OUTPUT_DIR/profiles" 2>/dev/null

# User profiles
mkdir -p "$OUTPUT_DIR/profiles/users"
for home in /home/* /root; do
    [[ -d "$home" ]] || continue
    user=$(basename "$home")
    mkdir -p "$OUTPUT_DIR/profiles/users/$user"
    for profile in .bashrc .bash_profile .profile .zshrc .bash_aliases; do
        [[ -f "$home/$profile" ]] && cp "$home/$profile" "$OUTPUT_DIR/profiles/users/$user/" 2>/dev/null
    done
done

# ==============================================================================
# CRON JOBS
# ==============================================================================
log "Backing up cron jobs..."
backup_item /etc/crontab "$OUTPUT_DIR/cron"
backup_item /etc/cron.d "$OUTPUT_DIR/cron" 2>/dev/null
backup_item /etc/cron.daily "$OUTPUT_DIR/cron" 2>/dev/null
backup_item /etc/cron.hourly "$OUTPUT_DIR/cron" 2>/dev/null
backup_item /etc/cron.weekly "$OUTPUT_DIR/cron" 2>/dev/null
backup_item /etc/cron.monthly "$OUTPUT_DIR/cron" 2>/dev/null

# User crontabs
mkdir -p "$OUTPUT_DIR/cron/user_crontabs"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l > "$OUTPUT_DIR/cron/user_crontabs/${user}.cron" 2>/dev/null
    # Remove empty files
    [[ -s "$OUTPUT_DIR/cron/user_crontabs/${user}.cron" ]] || rm -f "$OUTPUT_DIR/cron/user_crontabs/${user}.cron"
done

# ==============================================================================
# FIREWALL RULES
# ==============================================================================
log "Backing up firewall rules..."

# iptables
if command -v iptables-save &>/dev/null; then
    iptables-save > "$OUTPUT_DIR/firewall/iptables.rules" 2>/dev/null && \
        log "Backed up iptables rules"
fi

if command -v ip6tables-save &>/dev/null; then
    ip6tables-save > "$OUTPUT_DIR/firewall/ip6tables.rules" 2>/dev/null
fi

# nftables
if command -v nft &>/dev/null; then
    nft list ruleset > "$OUTPUT_DIR/firewall/nftables.rules" 2>/dev/null && \
        log "Backed up nftables rules"
fi

# firewalld
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all-zones > "$OUTPUT_DIR/firewall/firewalld.rules" 2>/dev/null && \
        log "Backed up firewalld rules"
fi

# ufw
if command -v ufw &>/dev/null; then
    ufw status verbose > "$OUTPUT_DIR/firewall/ufw.rules" 2>/dev/null && \
        log "Backed up ufw rules"
fi

# ==============================================================================
# SYSTEM CONFIGURATION
# ==============================================================================
log "Backing up system configuration..."
backup_item /etc/hosts "$OUTPUT_DIR/system"
backup_item /etc/resolv.conf "$OUTPUT_DIR/system"
backup_item /etc/fstab "$OUTPUT_DIR/system"
backup_item /etc/hostname "$OUTPUT_DIR/system"
backup_item /etc/sysctl.conf "$OUTPUT_DIR/system"
backup_item /etc/sysctl.d "$OUTPUT_DIR/system" 2>/dev/null
backup_item /etc/ld.so.preload "$OUTPUT_DIR/system" 2>/dev/null
backup_item /etc/ld.so.conf "$OUTPUT_DIR/system"
backup_item /etc/ld.so.conf.d "$OUTPUT_DIR/system" 2>/dev/null

# ==============================================================================
# SERVICES
# ==============================================================================
log "Backing up service configuration..."

# List enabled services
systemctl list-unit-files --state=enabled > "$OUTPUT_DIR/services/enabled_services.txt" 2>/dev/null
systemctl list-units --type=service --state=running > "$OUTPUT_DIR/services/running_services.txt" 2>/dev/null

# Backup custom systemd services
mkdir -p "$OUTPUT_DIR/services/custom"
find /etc/systemd/system -maxdepth 1 -name "*.service" -type f 2>/dev/null | while read -r svc; do
    cp "$svc" "$OUTPUT_DIR/services/custom/" 2>/dev/null
done

# ==============================================================================
# BASELINE SNAPSHOTS
# ==============================================================================
log "Creating system baseline..."

# Network listeners
if command -v ss &>/dev/null; then
    ss -tlnp > "$OUTPUT_DIR/baseline/tcp_listeners.txt" 2>/dev/null
    ss -ulnp > "$OUTPUT_DIR/baseline/udp_listeners.txt" 2>/dev/null
    ss -tnp > "$OUTPUT_DIR/baseline/tcp_established.txt" 2>/dev/null
else
    netstat -tlnp > "$OUTPUT_DIR/baseline/tcp_listeners.txt" 2>/dev/null
    netstat -ulnp > "$OUTPUT_DIR/baseline/udp_listeners.txt" 2>/dev/null
fi

# Running processes
ps auxf > "$OUTPUT_DIR/baseline/processes.txt" 2>/dev/null

# Loaded kernel modules
lsmod > "$OUTPUT_DIR/baseline/kernel_modules.txt" 2>/dev/null

# Environment
env > "$OUTPUT_DIR/baseline/environment.txt" 2>/dev/null
echo "$PATH" > "$OUTPUT_DIR/baseline/path.txt"

# Users currently logged in
w > "$OUTPUT_DIR/baseline/logged_in_users.txt" 2>/dev/null
last -n 50 > "$OUTPUT_DIR/baseline/last_logins.txt" 2>/dev/null

# Package list
if command -v dpkg &>/dev/null; then
    dpkg -l > "$OUTPUT_DIR/baseline/installed_packages.txt" 2>/dev/null
elif command -v rpm &>/dev/null; then
    rpm -qa > "$OUTPUT_DIR/baseline/installed_packages.txt" 2>/dev/null
fi

# ==============================================================================
# TRUSTED BINARY BACKUP
# ==============================================================================
log "Backing up trusted system binaries..."
mkdir -p "$OUTPUT_DIR/trusted_binaries"

# Critical binaries that are often trojanized
CRITICAL_BINS=(
    "cat" "ls" "ps" "netstat" "ss" "find" "grep" "awk" "sed"
    "bash" "sh" "sudo" "su" "passwd" "login" "sshd"
    "curl" "wget" "nc" "id" "whoami" "w" "who" "last"
    "iptables" "ip" "ifconfig" "route" "lsof" "top"
    "crontab" "systemctl" "journalctl" "chown" "chmod"
)

for bin in "${CRITICAL_BINS[@]}"; do
    bin_path=$(command -v "$bin" 2>/dev/null)
    if [[ -n "$bin_path" && -f "$bin_path" ]]; then
        cp "$bin_path" "$OUTPUT_DIR/trusted_binaries/" 2>/dev/null
        # Also store the hash for verification
        sha256sum "$bin_path" >> "$OUTPUT_DIR/trusted_binaries/hashes.sha256" 2>/dev/null
    fi
done

log "Backed up $(ls -1 "$OUTPUT_DIR/trusted_binaries" 2>/dev/null | grep -v hashes | wc -l) binaries"
echo ""
echo "To use trusted binaries if system is compromised:"
echo "  export PATH=$OUTPUT_DIR/trusted_binaries:\$PATH"

# ==============================================================================
# CREATE MANIFEST
# ==============================================================================
log "Creating backup manifest..."
{
    echo "=========================================="
    echo "SYSTEM BACKUP MANIFEST"
    echo "=========================================="
    echo ""
    echo "Hostname: $HOSTNAME"
    echo "Timestamp: $TIMESTAMP"
    echo "Date: $(date)"
    echo "Backup Directory: $OUTPUT_DIR"
    echo ""
    echo "System Information:"
    echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "  Kernel: $(uname -r)"
    echo "  Architecture: $(uname -m)"
    echo ""
    echo "Files Backed Up:"
    find "$OUTPUT_DIR" -type f | wc -l
    echo ""
    echo "Backup Size:"
    du -sh "$OUTPUT_DIR"
    echo ""
    echo "Directory Contents:"
    find "$OUTPUT_DIR" -type f | sort
} > "$OUTPUT_DIR/MANIFEST.txt"

# Set secure permissions
chmod -R 600 "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

# ==============================================================================
# COMPRESSION AND ENCRYPTION
# ==============================================================================
if [[ "$COMPRESS" == "true" ]]; then
    log "Creating compressed archive..."
    archive_name="${OUTPUT_DIR}.tar.gz"
    tar -czf "$archive_name" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null

    if [[ "$ENCRYPT" == "true" ]]; then
        if command -v gpg &>/dev/null; then
            log "Encrypting backup..."
            read -rsp "Enter encryption password: " password
            echo ""
            echo "$password" | gpg --batch --yes --passphrase-fd 0 -c "$archive_name" 2>/dev/null
            rm -f "$archive_name"
            archive_name="${archive_name}.gpg"
            log "Encrypted archive created: $archive_name"
        else
            warn "gpg not found, skipping encryption"
        fi
    else
        log "Archive created: $archive_name"
    fi

    # Optionally remove uncompressed directory
    # rm -rf "$OUTPUT_DIR"
fi

# ==============================================================================
# SUMMARY
# ==============================================================================
echo ""
echo "========================================"
echo "BACKUP COMPLETE"
echo "========================================"
echo ""
echo "Backup location: $OUTPUT_DIR"
[[ "$COMPRESS" == "true" ]] && echo "Archive: ${archive_name:-$OUTPUT_DIR.tar.gz}"
echo ""
echo "Quick verification:"
echo "  Total files: $(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l)"
echo "  Total size: $(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)"
echo ""
echo "To restore a file:"
echo "  cp $OUTPUT_DIR/<path>/<file> /original/location/"
echo ""
echo "To compare with current system:"
echo "  diff $OUTPUT_DIR/auth/passwd /etc/passwd"
echo "========================================"

exit 0
