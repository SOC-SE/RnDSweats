#!/bin/bash

JAIL_FILE="/etc/fail2ban/jail.local"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[-] Error: This script must be run as root."
        exit 1
    fi
}

detect_package_manager() {
    if command -v dnf &> /dev/null; then
        PM="dnf"; INSTALL="dnf install -y"; UPDATE="dnf makecache"
    elif command -v yum &> /dev/null; then
        PM="yum"; INSTALL="yum install -y"; UPDATE="yum makecache"
    elif command -v apt-get &> /dev/null; then
        PM="apt-get"; INSTALL="apt-get install -y"; UPDATE="apt-get update"
    elif command -v pacman &> /dev/null; then
        PM="pacman"; INSTALL="pacman -Sy --noconfirm"; UPDATE="pacman -Sy"
    else
        echo "[-] Unsupported package manager. Install manually."
        exit 1
    fi
}

detect_ssh_log() {
    # Auto-detect where SSH logs actually live to avoid Fail2Ban startup errors
    if [ -f "/var/log/auth.log" ]; then
        SSH_LOG="/var/log/auth.log"
    elif [ -f "/var/log/secure" ]; then
        SSH_LOG="/var/log/secure"
    else
        # Fallback to systemd backend if no files found
        SSH_LOG="systemd"
    fi
    echo "Detected SSH Log source: $SSH_LOG"
}


install_fail2ban() {
    echo "Updating package lists..."
    $UPDATE > /dev/null 2>&1
    
    echo "Installing Fail2Ban..."
    $INSTALL fail2ban > /dev/null 2>&1 || {
        echo "Install failed. Attempting EPEL (RHEL/CentOS)..."
        if [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
            $INSTALL epel-release > /dev/null 2>&1
            $UPDATE > /dev/null 2>&1
            $INSTALL fail2ban > /dev/null 2>&1
        fi
    }

    echo "Configuring Jail..."
    detect_ssh_log
    
    # If using log files
    if [ "$SSH_LOG" != "systemd" ]; then
        cat <<EOF > $JAIL_FILE
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = $SSH_LOG
maxretry = 3
findtime = 600
bantime  = 86400
ignoreip = 127.0.0.1/8 ::1 
EOF
    else
        # If using systemd backend (modern/arch)
        cat <<EOF > $JAIL_FILE
[sshd]
enabled = true
port    = ssh
filter  = sshd
backend = systemd
maxretry = 3
findtime = 600
bantime  = 86400
ignoreip = 127.0.0.1/8 ::1
EOF
    fi

    echo "Restarting Fail2Ban..."
    if command -v systemctl &> /dev/null; then
        systemctl enable fail2ban
        systemctl restart fail2ban
        if systemctl is-active --quiet fail2ban; then
            echo "Fail2Ban is ACTIVE and protecting SSH."
        else
            echo "Fail2Ban failed to start. Check 'systemctl status fail2ban'."
        fi
    else
        service fail2ban restart
    fi
}

unblock_ip() {
    read -p "Enter IP to unblock: " UNBAN_IP
    if [[ -z "$UNBAN_IP" ]]; then echo "Invalid IP"; return; fi
    fail2ban-client set sshd unbanip "$UNBAN_IP"
    echo "Unban command sent for $UNBAN_IP"
}

view_status() {
    echo "--- Fail2Ban SSHD Status ---"
    fail2ban-client status sshd 2>/dev/null || echo "Fail2Ban not running."
    echo ""
    echo "--- Currently Banned IPs ---"
    # Extract IPs from status command
    fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:"
}

disable_ssh() {
    echo -e "\033[1;31m[!!!] WARNING: THIS WILL STOP THE SSH SERVICE [!!!]\033[0m"
    echo "If you are connected via SSH, you will be disconnected immediately."
    read -p "Are you sure you want to proceed? (type 'yes'): " CONFIRM
    
    if [ "$CONFIRM" == "yes" ]; then
        echo "Stopping SSH Service..."
        if command -v systemctl &> /dev/null; then
            systemctl stop sshd 2>/dev/null || systemctl stop ssh
            systemctl disable sshd 2>/dev/null || systemctl disable ssh
        else
            service ssh stop
        fi
        echo "SSH Service Stopped."
    else
        echo "Aborted."
    fi
}

check_root
detect_package_manager

echo "=== FAIL2BAN MANAGER v3 ==="
echo "1. Install & Configure Fail2Ban (24hr Ban)"
echo "2. Unblock an IP Address"
echo "3. View Status & Banned IPs"
echo "4. Disable SSH Service"
echo "5. Exit"
read -p "Choice: " CHOICE

case $CHOICE in
    1) install_fail2ban ;;
    2) unblock_ip ;;
    3) view_status ;;
    4) disable_ssh ;;
    5) exit 0 ;;
    *) echo "Invalid option" ;;
esac