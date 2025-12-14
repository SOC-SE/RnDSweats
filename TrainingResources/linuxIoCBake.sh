#!/bin/bash

# Training Infrastructure Setup Script
# INTENT: Creates IoCs, persistence, and misconfigurations for incident response training.
# WARNING: This script makes the system INSECURE and ANNOYING. Use only on disposable VMs.

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

echo "!!! WARNING !!!"
echo "You are about to intentionally compromise this machine for training purposes."
echo "Services will be stopped, software removed, and security weakened."
read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# ==========================================
# 1. Random User Creation
# ==========================================
create_random_users() {
    echo "[*] Creating random users..."
    # List of plausible base names
    NAMES=("sysadmim" "backup" "webmaster" "deploy" "monitor" "analyst" "devops" "kafka" "splumk" "jenkins")
    
    # Determine random count (between 3 and 8)
    COUNT=$(( ( RANDOM % 6 ) + 3 ))

    for (( i=0; i<$COUNT; i++ )); do
        # Pick a random name and append a number to ensure uniqueness
        BASE=${NAMES[$RANDOM % ${#NAMES[@]}]}
        USERNAME="${BASE}_$(( RANDOM % 100 ))"
        
        # Randomly decide shell and group
        if (( RANDOM % 2 )); then
            SHELL="/bin/bash"
            GROUP="sudo" # Give some sudo access to make it spicy
        else
            SHELL="/bin/false"
            GROUP="nogroup"
        fi

        useradd -m -s "$SHELL" "$USERNAME"
        # Add to sudo if selected
        if [[ "$GROUP" == "sudo" ]]; then
            usermod -aG sudo "$USERNAME"
        fi
        
        # Set a default password (trainers should know this, or leave it locked)
        echo "$USERNAME:Password123!" | chpasswd
        echo "    Created user: $USERNAME ($SHELL)"
    done
}

# ==========================================
# 2. Cron Job: Fake Root Credential Dump
# ==========================================
create_cred_dump_cron() {
    echo "[*] Creating malicious cron job..."
    # We simulate the dump. Actual password stealing requires more complex tools.
    # This creates the artifact students need to find.
    
    DUMP_FILE="/tmp/.root_creds_$(date +%s).txt"
    CRON_CMD="echo 'root_hash_dump_simulation' > $DUMP_FILE && chmod 777 $DUMP_FILE"
    
    # Add to root's crontab randomly (every 1-59 minutes)
    MINUTE=$(( RANDOM % 59 ))
    (crontab -l 2>/dev/null; echo "$MINUTE * * * * $CRON_CMD") | crontab -
    echo "    Cron created to dump data to $DUMP_FILE"
}

# ==========================================
# 3. Systemd: Serivce Stop & Git Uninstall
# ==========================================
create_disruptive_service() {
    echo "[*] Creating disruptive systemd service (Apache/Git)..."
    SERVICE_NAME="cleanup_maintenance_$(((RANDOM%1000)+1000)).service"
    TIMER_NAME="${SERVICE_NAME%.*}.timer"

    # Create the script that does the damage
    SCRIPT_PATH="/usr/local/bin/sys_maint_$(date +%s).sh"
    
    cat <<EOF > "$SCRIPT_PATH"
#!/bin/bash
wall "SYSTEM ALERT: Apache is stopping and Git is being removed for 'maintenance'."
systemctl stop apache2 2>/dev/null || systemctl stop httpd 2>/dev/null
apt-get remove -y git 2>/dev/null || yum remove -y git 2>/dev/null
EOF
    chmod +x "$SCRIPT_PATH"

    # Create Service Unit
    cat <<EOF > "/etc/systemd/system/$SERVICE_NAME"
[Unit]
Description=System Maintenance Routine

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
EOF

    # Create Timer Unit (Every 5 minutes)
    cat <<EOF > "/etc/systemd/system/$TIMER_NAME"
[Unit]
Description=Run maintenance every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$TIMER_NAME"
    echo "    Created disruptive timer: $TIMER_NAME"
}

# ==========================================
# 4. Systemd: Insecure SSH Installer
# ==========================================
create_insecure_ssh_service() {
    echo "[*] Creating insecure SSH installer..."
    SERVICE_NAME="remote_access_helper.service"
    TIMER_NAME="remote_access_helper.timer"
    SCRIPT_PATH="/usr/local/bin/fix_ssh.sh"

    cat <<EOF > "$SCRIPT_PATH"
#!/bin/bash
# Install SSH if missing
apt-get install -y openssh-server 2>/dev/null || yum install -y openssh-server 2>/dev/null

# Apply insecure config
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Allow empty passwords (very bad)
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
EOF
    chmod +x "$SCRIPT_PATH"

    # Timer running every 7 minutes
    cat <<EOF > "/etc/systemd/system/$TIMER_NAME"
[Unit]
Description=Ensure Remote Access

[Timer]
OnBootSec=1min
OnUnitActiveSec=7min

[Install]
WantedBy=timers.target
EOF

    cat <<EOF > "/etc/systemd/system/$SERVICE_NAME"
[Unit]
Description=Helper for SSH

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
EOF

    systemctl daemon-reload
    systemctl enable --now "$TIMER_NAME"
    echo "    Created insecure SSH timer: $TIMER_NAME"
}

# ==========================================
# 5. Annoying Functions
# ==========================================

# Annoyance 1: Corrupt Hosts File
# Maps google.com to localhost to confuse students trying to google solutions
annoy_dns() {
    echo "[*] Annoyance: Modifying /etc/hosts..."
    echo "127.0.0.1 google.com" >> /etc/hosts
    echo "127.0.0.1 www.google.com" >> /etc/hosts
}

# Annoyance 2: The "ls" alias
# Aliases 'ls' to 'ls -la | grep "conf"' to hide files and confuse output
annoy_bashrc() {
    echo "[*] Annoyance: Poisoning .bashrc..."
    # Apply to root and any user with /home directory
    for home_dir in /root /home/*; do
        if [[ -f "$home_dir/.bashrc" ]]; then
            echo "alias ls='echo \"Loading...\" && sleep 2 && ls -la'" >> "$home_dir/.bashrc"
        fi
    done
}

# Annoyance 3: Hidden Disk Space Consumer
# Creates a large hidden file to simulate a staged exfiltration archive
annoy_disk_space() {
    echo "[*] Annoyance: Creating hidden large file..."
    dd if=/dev/zero of=/var/log/.system_backup_$(date +%s).tar.gz bs=1M count=500 &>/dev/null
}

# Annoyance 4: Changed Message of the Day (MOTD)
# Psychological warfare - taunting the team
annoy_motd() {
    echo "[*] Annoyance: Changing MOTD..."
    echo "YOU ARE BEING WATCHED. SILENCE IS GOLDEN." > /etc/motd
}

# Annoyance 5: Permissions Chaos
# Make a common utility non-executable (e.g., ping)
annoy_permissions() {
    echo "[*] Annoyance: Removing execute permissions from 'ping'..."
    chmod -x $(which ping)
}

# ==========================================
# Execution
# ==========================================

create_random_users
create_cred_dump_cron
create_disruptive_service
create_insecure_ssh_service

# Randomly select 3 of the 5 annoyances to run
funcs=(annoy_dns annoy_bashrc annoy_disk_space annoy_motd annoy_permissions)
# Shuffle and pick 3
for i in $(shuf -i 0-4 -n 3); do
    ${funcs[$i]}
done

echo
echo "DONE. The system is now compromised and training-ready."
echo "Good luck to your Blue Team!"