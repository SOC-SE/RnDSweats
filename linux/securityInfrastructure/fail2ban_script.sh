#!/bin/bash

# Fail2Ban Manager v5
# Supports: Debian, Ubuntu, Kali, Fedora, RHEL/CentOS, Arch
# Fix: Uses paths-overrides.local to correctly handle missing auth.log
#      on minimal Debian/Ubuntu installs instead of fighting jail.local

JAIL_FILE="/etc/fail2ban/jail.local"
PATHS_OVERRIDE="/etc/fail2ban/paths-overrides.local"

# ─────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] Error: This script must be run as root."
        exit 1
    fi
}

# ─────────────────────────────────────────────
# PACKAGE MANAGER + DISTRO DETECTION
# ─────────────────────────────────────────────
detect_package_manager() {
    if command -v dnf &> /dev/null; then
        PM="dnf"; INSTALL="dnf install -y"; UPDATE="dnf makecache"
        DISTRO_FAMILY="rhel"
    elif command -v yum &> /dev/null; then
        PM="yum"; INSTALL="yum install -y"; UPDATE="yum makecache"
        DISTRO_FAMILY="rhel"
    elif command -v apt-get &> /dev/null; then
        PM="apt-get"; INSTALL="apt-get install -y"; UPDATE="apt-get update"
        DISTRO_FAMILY="debian"
    elif command -v pacman &> /dev/null; then
        PM="pacman"; INSTALL="pacman -Sy --noconfirm"; UPDATE="pacman -Sy"
        DISTRO_FAMILY="arch"
    else
        echo "[-] Unsupported package manager. Install fail2ban manually."
        exit 1
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID,,}"
        echo "[*] Detected: $PRETTY_NAME (family: $DISTRO_FAMILY)"
    fi
}

# ─────────────────────────────────────────────
# SSH LOG DETECTION
# ─────────────────────────────────────────────
detect_ssh_log() {
    echo "[*] Detecting SSH log source..."

    if [ -f "/var/log/auth.log" ]; then
        SSH_LOG="/var/log/auth.log"

    elif [ -f "/var/log/secure" ]; then
        SSH_LOG="/var/log/secure"

    else
        echo "[!] No SSH log file found. Attempting to install rsyslog..."

        if [[ "$DISTRO_FAMILY" == "debian" || "$DISTRO_FAMILY" == "rhel" ]]; then
            $INSTALL rsyslog > /dev/null 2>&1
            systemctl enable rsyslog > /dev/null 2>&1
            systemctl start rsyslog > /dev/null 2>&1
            sleep 2
        fi

        if [ -f "/var/log/auth.log" ]; then
            SSH_LOG="/var/log/auth.log"
            echo "[+] rsyslog installed. Using /var/log/auth.log"
        elif [ -f "/var/log/secure" ]; then
            SSH_LOG="/var/log/secure"
            echo "[+] rsyslog installed. Using /var/log/secure"
        else
            SSH_LOG="systemd"
            echo "[!] No log file available. Using systemd journal backend."
        fi
    fi

    echo "[*] SSH log source: $SSH_LOG"
}

# ─────────────────────────────────────────────
# FIREWALL CHECK
# ─────────────────────────────────────────────
check_firewall_backend() {
    if ! command -v iptables &> /dev/null && ! command -v nft &> /dev/null; then
        echo "[!] No firewall backend found. Installing iptables..."
        $INSTALL iptables > /dev/null 2>&1 && \
            echo "[+] iptables installed." || \
            echo "[-] Failed to install iptables. Banning may not work."
    else
        echo "[+] Firewall backend available."
    fi
}

# ─────────────────────────────────────────────
# WRITE CONFIGS
#
# KEY FIX: paths-overrides.local is loaded LAST
# by fail2ban, overriding the hardcoded
# sshd_log = /var/log/auth.log in paths-common.conf
# This prevents the "Have not found any log file"
# crash on minimal Debian/Ubuntu with no auth.log
# ─────────────────────────────────────────────
write_configs() {
    if [ "$SSH_LOG" != "systemd" ]; then
        cat <<EOF > "$PATHS_OVERRIDE"
[DEFAULT]
sshd_log = $SSH_LOG
sshd_backend = auto
EOF

        cat <<EOF > "$JAIL_FILE"
[DEFAULT]
backend = auto

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 3
findtime = 600
bantime  = 86400
ignoreip = 127.0.0.1/8 ::1
EOF
        echo "[+] Configured with log file: $SSH_LOG"

    else
        # Empty sshd_log in paths-overrides.local prevents fail2ban from
        # trying to open the non-existent /var/log/auth.log from defaults
        cat <<EOF > "$PATHS_OVERRIDE"
[DEFAULT]
sshd_log =
sshd_backend = systemd
EOF

        cat <<EOF > "$JAIL_FILE"
[DEFAULT]
backend = auto

[sshd]
enabled      = true
port         = ssh
filter       = sshd
backend      = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service
logpath      =
maxretry     = 3
findtime     = 600
bantime      = 86400
ignoreip     = 127.0.0.1/8 ::1
EOF
        echo "[+] Configured with systemd journal backend."
    fi
}

# ─────────────────────────────────────────────
# INSTALL FAIL2BAN
# ─────────────────────────────────────────────
install_fail2ban() {
    echo "[*] Updating package lists..."
    $UPDATE > /dev/null 2>&1

    echo "[*] Installing Fail2Ban..."
    $INSTALL fail2ban > /dev/null 2>&1 || {
        if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
            echo "[!] Install failed. Trying EPEL..."
            $INSTALL epel-release > /dev/null 2>&1
            $UPDATE > /dev/null 2>&1
            $INSTALL fail2ban > /dev/null 2>&1
        fi
    }

    if ! command -v fail2ban-server &> /dev/null; then
        echo "[-] Fail2Ban installation failed. Exiting."
        exit 1
    fi
    echo "[+] $(fail2ban-server --version 2>&1 | head -1) installed."

    check_firewall_backend
    detect_ssh_log
    write_configs

    echo "[*] Validating configuration..."
    if ! fail2ban-client -t > /dev/null 2>&1; then
        echo "[-] Configuration test failed:"
        fail2ban-client -t 2>&1
        exit 1
    fi
    echo "[+] Configuration test passed."

    echo "[*] Starting Fail2Ban..."
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        echo "[+] Fail2Ban is ACTIVE and protecting SSH."
        echo ""
        fail2ban-client status sshd 2>/dev/null || true
    else
        echo "[-] Fail2Ban failed to start. Diagnostic info:"
        journalctl -u fail2ban -n 15 --no-pager
    fi
}

# ─────────────────────────────────────────────
# UNBLOCK IP
# ─────────────────────────────────────────────
unblock_ip() {
    read -p "Enter IP to unblock: " UNBAN_IP
    if [[ -z "$UNBAN_IP" ]]; then echo "[-] Invalid IP."; return; fi
    fail2ban-client set sshd unbanip "$UNBAN_IP" && \
        echo "[+] Unbanned: $UNBAN_IP" || \
        echo "[-] Failed. Is Fail2Ban running?"
}

# ─────────────────────────────────────────────
# VIEW STATUS
# ─────────────────────────────────────────────
view_status() {
    echo "--- Fail2Ban Service ---"
    systemctl is-active --quiet fail2ban && \
        echo "[+] RUNNING" || echo "[-] NOT running"
    echo ""
    echo "--- SSHD Jail Status ---"
    fail2ban-client status sshd 2>/dev/null || echo "[-] sshd jail not active."
    echo ""
    echo "--- Banned IPs ---"
    fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" || echo "None."
}

# ─────────────────────────────────────────────
# DISABLE SSH
# ─────────────────────────────────────────────
disable_ssh() {
    echo -e "\033[1;31m[!!!] WARNING: THIS WILL STOP THE SSH SERVICE [!!!]\033[0m"
    echo "If connected via SSH, you will be disconnected immediately."
    read -p "Type 'yes' to confirm: " CONFIRM
    if [ "$CONFIRM" == "yes" ]; then
        systemctl stop sshd 2>/dev/null || systemctl stop ssh
        systemctl disable sshd 2>/dev/null || systemctl disable ssh
        echo "[+] SSH service stopped and disabled."
    else
        echo "[*] Aborted."
    fi
}

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
check_root
detect_package_manager

echo ""
echo "=== FAIL2BAN MANAGER v5 ==="
echo "1. Install & Configure Fail2Ban (24hr Ban)"
echo "2. Unblock an IP Address"
echo "3. View Status & Banned IPs"
echo "4. Disable SSH Service"
echo "5. Exit"
echo ""
read -p "Choice: " CHOICE

case $CHOICE in
    1) install_fail2ban ;;
    2) unblock_ip ;;
    3) view_status ;;
    4) disable_ssh ;;
    5) exit 0 ;;
    *) echo "[-] Invalid option." ;;
esac
