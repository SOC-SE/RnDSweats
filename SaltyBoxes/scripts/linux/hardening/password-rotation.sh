#!/bin/bash
# ==============================================================================
# Password Rotation Script - Linux
# Change passwords for specified users or all human users
# For Salt-GUI / CCDC Competition Use
#
# By Samuel Brucker 2025-2026
# ==============================================================================

set -euo pipefail

# Usage: password-rotation.sh [username] [password]
# If no username specified, rotates all human users (UID >= 1000)
# If no password specified, generates a random one

TARGET_USER="${1:-}"
NEW_PASSWORD="${2:-}"

echo "========================================"
echo "PASSWORD ROTATION - $(hostname)"
echo "Time: $(date)"
echo "========================================"

# Generate random password if not provided
generate_password() {
    # 16 char password with mixed case, numbers, symbols
    openssl rand -base64 16 | tr -d '/+=' | head -c 16
}

change_user_password() {
    local user="$1"
    local password="$2"

    # Check if user exists
    if ! id "$user" &>/dev/null; then
        echo "  SKIP: User '$user' does not exist"
        return 1
    fi

    # Change the password
    echo "$user:$password" | chpasswd

    # Force password change on next login (optional - comment out for CCDC)
    # chage -d 0 "$user"

    echo "  OK: Password changed for '$user'"
    return 0
}

if [ -n "$TARGET_USER" ]; then
    # Single user mode
    echo -e "\n[SINGLE USER MODE]"
    echo "----------------------------------------"

    if [ -z "$NEW_PASSWORD" ]; then
        NEW_PASSWORD=$(generate_password)
        echo "Generated password for $TARGET_USER: $NEW_PASSWORD"
    fi

    change_user_password "$TARGET_USER" "$NEW_PASSWORD"
else
    # All human users mode
    echo -e "\n[ALL HUMAN USERS MODE]"
    echo "----------------------------------------"

    # Get all users with UID >= 1000 and valid shell
    HUMAN_USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd)

    if [ -z "$HUMAN_USERS" ]; then
        echo "No human users found"
        exit 0
    fi

    echo "Users to rotate:"
    echo "$HUMAN_USERS" | tr '\n' ' '
    echo -e "\n"

    echo "New Credentials:"
    echo "----------------------------------------"
    for user in $HUMAN_USERS; do
        if [ -z "$NEW_PASSWORD" ]; then
            user_password=$(generate_password)
        else
            user_password="$NEW_PASSWORD"
        fi

        if change_user_password "$user" "$user_password"; then
            printf "%-20s %s\n" "$user:" "$user_password"
        fi
    done
fi

echo -e "\n========================================"
echo "PASSWORD ROTATION COMPLETE"
echo "========================================"
