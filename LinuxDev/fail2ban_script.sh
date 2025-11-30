#!/bin/bash

LOGFILE="/var/log/failed_login_ips.log"
CRONFILE="/etc/cron.d/fail2ban-log"

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

echo "Updating package lists..."
$UPDATE

echo "Installing fail2ban..."
$INSTALL fail2ban

echo "Enabling and starting fail2ban service..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
else
    sudo service fail2ban start
fi

# Configure fail2ban for SSH
echo "Configuring fail2ban for SSH..."
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

# Create custom log file
echo "Setting up custom log file at $LOGFILE..."
sudo touch $LOGFILE
sudo chmod 644 $LOGFILE
sudo chown root:root $LOGFILE

# Detect SSH unit name (ssh vs sshd)
if systemctl list-unit-files | grep -q "^ssh.service"; then
    SSHUNIT="ssh"
else
    SSHUNIT="sshd"
fi

# Create cron job to append all failed attempts every minute
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

echo "Setup complete. Fail2ban is running, and ALL failed login IPs will be appended to $LOGFILE every minute."
