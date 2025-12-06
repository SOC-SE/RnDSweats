#!/bin/sh

# ==============================================================================
# Alpine Console SSH Manager (Standard sh version)
# Purpose: Configure SSH keys, transmit to admin, lock down passwords.
#          Includes a reversion mechanism to restore password access.
# Run this directly on the Alpine Server Console.
# ==============================================================================

# ANSI Color Codes for standard shell
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

KEY_NAME="id_ed25519_alpine_console"
KEY_PATH="/root/.ssh/$KEY_NAME"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_CONFIG="/etc/ssh/sshd_config.bak_console"

# Helper functions for printing
print_info() { printf "${GREEN}[INFO]${RESET} %s\n" "$1"; }
print_warn() { printf "${YELLOW}[WARN]${RESET} %s\n" "$1"; }
print_err()  { printf "${RED}[ERROR]${RESET} %s\n" "$1"; }

# Check for Root
if [ "$(id -u)" -ne 0 ]; then
   print_err "This script must be run as root." 
   exit 1
fi

# ==============================================================================
# FUNCTION: Revert Changes
# ==============================================================================
revert_changes() {
    echo ""
    print_warn "REVERT MODE: Restoring Password Authentication..."
    
    # 1. Restore File or Edit
    if [ -f "$BACKUP_CONFIG" ]; then
        print_info "Restoring from backup ($BACKUP_CONFIG)..."
        cp "$BACKUP_CONFIG" "$SSHD_CONFIG"
    else
        print_warn "No backup found. Manually forcing configuration to 'yes'..."
        # Force Enable Passwords
        sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' "$SSHD_CONFIG"
        sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/' "$SSHD_CONFIG"
        # Ensure Root can login with password (emergency access)
        sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' "$SSHD_CONFIG"
    fi

    # 2. Restart SSHD
    print_info "Restarting SSH Service..."
    if rc-service sshd restart; then
        echo ""
        print_info "SUCCESS: Password authentication is ENABLED."
        print_info "You can now login via SSH using your root password."
    else
        print_err "Failed to restart SSHD. Check configuration."
    fi
}

# ==============================================================================
# FUNCTION: Setup SSH Keys & Lockdown
# ==============================================================================
setup_ssh() {
    echo ""
    print_info "STEP 1: Key Generation"
    # Ensure .ssh dir exists
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    if [ -f "$KEY_PATH" ]; then
        print_warn "Key already exists."
        printf "Overwrite? (y/N): "
        read REGEN
        case "$REGEN" in
            [Yy]*)
                rm "$KEY_PATH" "$KEY_PATH.pub"
                ssh-keygen -t ed25519 -f "$KEY_PATH" -C "root@alpine-console" -N "" > /dev/null
                print_info "New key generated."
                ;;
            *)
                print_info "Using existing key."
                ;;
        esac
    else
        ssh-keygen -t ed25519 -f "$KEY_PATH" -C "root@alpine-console" -N "" > /dev/null
        print_info "Key generated."
    fi

    # Authorize the key locally immediately
    # grep -qf might behave differently in strict sh/busybox, so we use a simpler check or just append
    cat "$KEY_PATH.pub" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    print_info "Key added to authorized_keys."

    echo ""
    print_info "STEP 2: Send Private Key to Workstation"
    echo "Since you are on the console, we need to send the PRIVATE key to your computer."
    echo "Please ensure your workstation (receiver) has SSH enabled (Remote Login)."
    echo ""
    
    printf "Workstation IP: "
    read TARGET_IP
    printf "Workstation Username: "
    read TARGET_USER

    print_info "Sending key to $TARGET_USER@$TARGET_IP..."
    scp "$KEY_PATH" "$TARGET_USER@$TARGET_IP:~/.ssh/${KEY_NAME}_private"

    if [ $? -eq 0 ]; then
        print_info "SUCCESS: Key sent."
        print_info "On your workstation, run: chmod 600 ~/.ssh/${KEY_NAME}_private"
    else
        echo ""
        print_err "SCP Failed. (Firewall? SSH Server not running on workstation?)"
        print_warn "Fallback: Printing Private Key to screen."
        print_warn "Copy the block below manually into a file on your workstation."
        echo "---------------------------------------------------------------"
        cat "$KEY_PATH"
        echo "---------------------------------------------------------------"
        printf "Press Enter after you have copied the key..."
        read PAUSED
    fi

    echo ""
    print_info "STEP 3: Disable Password Authentication"
    print_warn "Do not proceed unless you have confirmed you have the private key."
    printf "Disable passwords now? (y/N): "
    read CONFIRM

    case "$CONFIRM" in
        [Yy]*)
            # Backup
            cp "$SSHD_CONFIG" "$BACKUP_CONFIG"

            # Edit
            sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
            sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
            # Set Root to allow keys only
            sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"

            # Restart
            rc-service sshd restart
            print_info "SUCCESS: Server is now locked down. Key authentication only."
            ;;
        *)
            print_info "Cancelled. Passwords remain active."
            ;;
    esac
}

# ==============================================================================
# MAIN MENU
# ==============================================================================
clear
echo "${BLUE}========================================${RESET}"
echo "${BLUE}   Alpine Console SSH Manager (sh)      ${RESET}"
echo "${BLUE}========================================${RESET}"
echo "1. Setup (Generate Key -> Send -> Lockdown)"
echo "2. Revert (Re-enable Password Auth)"
echo "3. Exit"
echo ""
printf "Select an option [1-3]: "
read CHOICE

case $CHOICE in
    1) setup_ssh ;;
    2) revert_changes ;;
    3) exit 0 ;;
    *) echo "Invalid option." ;;
esac