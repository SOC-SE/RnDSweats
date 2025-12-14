#!/bin/bash

LOGFILE="/var/log/failed_login_ips.log"
CRONFILE="/etc/cron.d/fail2ban-log"

# Version 2 of the fail2ban script - addition of options, and more error handling for different distros
# Made using Copilot AI
# Script sets up Fail2Ban - made so that it should work on most linux distros; 
# after 3 failed ssh login attempts, it uses cron to add the ip address to the log file listed above, along with the timestamp
# after 3 failed attempts, fail2ban prevents the ip from establishing an ssh connection
# cron job runs every minute (timing can be changed below), and appends new info to the log file

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PM="apt-get"
    INSTALL="sudo apt-get install -y"
    UPDATE="sudo apt-get update -y"
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
    INSTALL="sudo dnf install -y"
    UPDATE="sudo dnf makecache -y"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"
    INSTALL="sudo yum install -y"
    UPDATE="sudo yum makecache -y"
elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
    INSTALL="sudo pacman -Sy --noconfirm"
    UPDATE="sudo pacman -Sy --noconfirm"
else
    echo "Unsupported package manager. Install fail2ban manually."
    exit 1
fi

# Detect SSH unit name (ssh vs sshd)
if systemctl list-unit-files | grep -q "^ssh.service"; then
    SSHUNIT="ssh"
else
    SSHUNIT="sshd"
fi

echo "Choose an option:"
echo "[1] Run Fail2Ban setup"
echo "[2] Unblock an IP address"
echo "[3] Disable SSH service"
read -p "Enter your choice [1-3]: " CHOICE

if [ "$CHOICE" == "2" ]; then
    read -p "Enter IP address to unblock: " UNBLOCK_IP
    sudo fail2ban-client set sshd unbanip "$UNBLOCK_IP"
    echo "IP $UNBLOCK_IP has been unblocked from Fail2Ban."
    exit 0
elif [ "$CHOICE" == "3" ]; then
    echo "Stopping SSH service ($SSHUNIT)..."
    sudo systemctl stop "$SSHUNIT"
    echo "SSH service stopped."
    exit 0
elif [ "$CHOICE" != "1" ]; then
    echo "Invalid option. Exiting."
    exit 1
fi

echo "Updating package lists..."
$UPDATE

echo "Installing fail2ban..."
$INSTALL fail2ban || {
    echo "Fail2Ban not found. Attempting to enable EPEL repository for Rocky Linux..."
    if [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        sudo $PM install -y epel-release
        $UPDATE
        $INSTALL fail2ban || {
            echo "Failed to install fail2ban even after enabling EPEL. Exiting."
            exit 1;
        }
    else
        echo "Fail2Ban installation failed. Exiting."
        exit 1;
    fi;
}

echo "Enabling and starting fail2ban service..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
else
    sudo service fail2ban start
fi

echo "Configuring fail2ban for SSH..."
sudo mkdir -p /etc/fail2ban
sudo bash -c 'cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = %(sshd_log)s
maxretry = 3
findtime = 600
bantime  = 3600
EOF'

if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart fail2ban
else
    sudo service fail2ban restart
fi

echo "Setting up custom log file at $LOGFILE..."
sudo touch $LOGFILE
sudo chmod 644 $LOGFILE
sudo chown root:root $LOGFILE

CRONLINE="* * * * * root /usr/bin/journalctl -u $SSHUNIT --no-pager | /bin/grep -F \"Failed password\" | /usr/bin/awk 'match(\$0, /from ([0-9a-fA-F:.]+)/, m){print \$1,\$2,\$3, \"IP:\", m[1]}' >> $LOGFILE"

echo "Creating cron job..."
echo "$CRONLINE" | sudo tee $CRONFILE > /dev/null
sudo chmod 644 $CRONFILE
sudo chown root:root $CRONFILE

if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart cron || sudo systemctl restart crond
else
    sudo service cron restart || sudo service crond restart
fi

echo "Setup complete. Fail2Ban is running, and ALL failed login IPs will be appended to $LOGFILE every minute."
