#!/bin/bash
# ==============================================================================
# Backup Critical Configs - Linux
# Create backups of critical system configurations before making changes
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${1:-/root/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$(hostname)_$TIMESTAMP"

echo "========================================"
echo "CONFIG BACKUP - $(hostname)"
echo "Time: $(date)"
echo "Backup Path: $BACKUP_PATH"
echo "========================================"

# Create backup directory
mkdir -p "$BACKUP_PATH"

echo -e "\n[1/8] BACKING UP USER/AUTH FILES"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/auth"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    if [ -f "$f" ]; then
        cp -p "$f" "$BACKUP_PATH/auth/" && echo "  Backed up: $f"
    fi
done
# Sudoers.d directory
if [ -d /etc/sudoers.d ]; then
    cp -rp /etc/sudoers.d "$BACKUP_PATH/auth/" && echo "  Backed up: /etc/sudoers.d/"
fi

echo -e "\n[2/8] BACKING UP SSH CONFIGURATION"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/ssh"
if [ -d /etc/ssh ]; then
    cp -rp /etc/ssh "$BACKUP_PATH/ssh/" && echo "  Backed up: /etc/ssh/"
fi
# User SSH keys
for home in /root /home/*; do
    if [ -d "$home/.ssh" ]; then
        user=$(basename "$home")
        mkdir -p "$BACKUP_PATH/ssh/users/$user"
        cp -rp "$home/.ssh" "$BACKUP_PATH/ssh/users/$user/" 2>/dev/null && echo "  Backed up: $home/.ssh/"
    fi
done

echo -e "\n[3/8] BACKING UP NETWORK CONFIGURATION"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/network"
# Common network config files
for f in /etc/hosts /etc/hostname /etc/resolv.conf /etc/nsswitch.conf; do
    if [ -f "$f" ]; then
        cp -p "$f" "$BACKUP_PATH/network/" && echo "  Backed up: $f"
    fi
done
# Network directories
for d in /etc/netplan /etc/sysconfig/network-scripts /etc/NetworkManager; do
    if [ -d "$d" ]; then
        cp -rp "$d" "$BACKUP_PATH/network/" 2>/dev/null && echo "  Backed up: $d/"
    fi
done

echo -e "\n[4/8] BACKING UP FIREWALL RULES"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/firewall"
# iptables
if command -v iptables &>/dev/null; then
    iptables-save > "$BACKUP_PATH/firewall/iptables.rules" 2>/dev/null && echo "  Backed up: iptables rules"
fi
if command -v ip6tables &>/dev/null; then
    ip6tables-save > "$BACKUP_PATH/firewall/ip6tables.rules" 2>/dev/null && echo "  Backed up: ip6tables rules"
fi
# nftables
if command -v nft &>/dev/null; then
    nft list ruleset > "$BACKUP_PATH/firewall/nftables.rules" 2>/dev/null && echo "  Backed up: nftables rules"
fi
# ufw
if [ -d /etc/ufw ]; then
    cp -rp /etc/ufw "$BACKUP_PATH/firewall/" && echo "  Backed up: /etc/ufw/"
fi
# firewalld
if [ -d /etc/firewalld ]; then
    cp -rp /etc/firewalld "$BACKUP_PATH/firewall/" && echo "  Backed up: /etc/firewalld/"
fi

echo -e "\n[5/8] BACKING UP SERVICE CONFIGURATIONS"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/services"
# Common service configs
service_configs=(
    "/etc/apache2"
    "/etc/httpd"
    "/etc/nginx"
    "/etc/mysql"
    "/etc/mariadb"
    "/etc/postgresql"
    "/etc/postfix"
    "/etc/dovecot"
    "/etc/samba"
    "/etc/vsftpd.conf"
    "/etc/proftpd"
    "/etc/bind"
    "/etc/named.conf"
)
for d in "${service_configs[@]}"; do
    if [ -e "$d" ]; then
        cp -rp "$d" "$BACKUP_PATH/services/" 2>/dev/null && echo "  Backed up: $d"
    fi
done

echo -e "\n[6/8] BACKING UP CRON JOBS"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/cron"
cp -rp /etc/cron* "$BACKUP_PATH/cron/" 2>/dev/null && echo "  Backed up: /etc/cron*"
if [ -d /var/spool/cron ]; then
    cp -rp /var/spool/cron "$BACKUP_PATH/cron/spool" 2>/dev/null && echo "  Backed up: /var/spool/cron"
fi

echo -e "\n[7/8] BACKING UP SYSTEMD UNITS"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/systemd"
# Only backup custom/modified units
if [ -d /etc/systemd/system ]; then
    find /etc/systemd/system -maxdepth 1 -type f -name "*.service" -exec cp {} "$BACKUP_PATH/systemd/" \; 2>/dev/null
    echo "  Backed up custom systemd units"
fi

echo -e "\n[8/8] BACKING UP PAM CONFIGURATION"
echo "----------------------------------------"
mkdir -p "$BACKUP_PATH/pam"
if [ -d /etc/pam.d ]; then
    cp -rp /etc/pam.d "$BACKUP_PATH/pam/" && echo "  Backed up: /etc/pam.d/"
fi
for f in /etc/security/limits.conf /etc/security/access.conf; do
    if [ -f "$f" ]; then
        cp -p "$f" "$BACKUP_PATH/pam/" && echo "  Backed up: $f"
    fi
done

# Create tarball
echo -e "\n----------------------------------------"
echo "Creating compressed archive..."
tar -czf "${BACKUP_PATH}.tar.gz" -C "$BACKUP_DIR" "$(basename $BACKUP_PATH)"
rm -rf "$BACKUP_PATH"

# Calculate size
BACKUP_SIZE=$(du -h "${BACKUP_PATH}.tar.gz" | cut -f1)

echo -e "\n========================================"
echo "BACKUP COMPLETE"
echo "Archive: ${BACKUP_PATH}.tar.gz"
echo "Size: $BACKUP_SIZE"
echo "========================================"

# Output the path for Salt to capture
echo "BACKUP_FILE=${BACKUP_PATH}.tar.gz"
