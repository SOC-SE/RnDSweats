#!/bin/bash
# ==============================================================================
# Script Name: sshKeyPurge.sh
# Description: Removes SSH keys (authorized_keys and private keys) with forensic
#              logging before secure deletion. Preserves evidence while removing
#              attacker persistence.
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./sshKeyPurge.sh [options]
#
# Options:
#   -h, --help           Show this help message
#   -l, --log-dir        Directory for key backups (default: /root/ssh_key_logs)
#   -a, --authorized     Only remove authorized_keys files
#   -p, --private        Only remove private keys
#   -u, --user           Only process specific user
#   -n, --dry-run        Show what would be removed without removing
#   -f, --force          Skip confirmation prompt
#
# What Gets Removed:
#   - ~/.ssh/authorized_keys and authorized_keys2
#   - Private keys (id_rsa, id_dsa, id_ecdsa, id_ed25519)
#   - Does NOT remove host keys (/etc/ssh/ssh_host_*)
#
# Supported Systems:
#   - Ubuntu 20.04+
#   - Fedora 38+
#   - Rocky/Alma/Oracle Linux 8+
#   - Debian 11+
#   - Alpine Linux
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - Aborted by user
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
LOG_DIR="/root/ssh_key_logs"
ONLY_AUTHORIZED=false
ONLY_PRIVATE=false
SPECIFIC_USER=""
DRY_RUN=false
FORCE=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# --- Counters ---
KEYS_FOUND=0
KEYS_REMOVED=0

# --- Helper Functions ---
usage() {
    head -40 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

removed() {
    echo -e "${MAGENTA}[REMOVED]${NC} $1"
}

dry_run_msg() {
    echo -e "${BLUE}[DRY-RUN]${NC} Would remove: $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -l|--log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        -a|--authorized)
            ONLY_AUTHORIZED=true
            shift
            ;;
        -p|--private)
            ONLY_PRIVATE=true
            shift
            ;;
        -u|--user)
            SPECIFIC_USER="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Functions ---
get_authorized_keys_paths() {
    # Parse sshd_config for AuthorizedKeysFile directive
    local config_paths
    config_paths=$(grep -iE "^AuthorizedKeysFile" /etc/ssh/sshd_config 2>/dev/null | awk '{$1=""; print $0}' | sed 's/^[ \t]*//')

    if [[ -z "$config_paths" ]]; then
        # Default paths
        echo ".ssh/authorized_keys .ssh/authorized_keys2"
    else
        echo "$config_paths"
    fi
}

get_users() {
    if [[ -n "$SPECIFIC_USER" ]]; then
        echo "$SPECIFIC_USER"
    else
        # Get users with valid login shells and UID >= 1000, plus root
        awk -F: '($3 >= 1000 || $3 == 0) && $7 !~ /(false|nologin|sync|shutdown|halt)$/ { print $1 }' /etc/passwd
    fi
}

is_key_file() {
    local file="$1"
    # Check if file contains SSH key patterns
    if grep -qE 'BEGIN (OPENSSH|RSA|DSA|EC|PRIVATE) KEY|^ssh-(rsa|ed25519|ecdsa|dss) ' "$file" 2>/dev/null; then
        return 0
    fi
    return 1
}

backup_and_remove() {
    local file="$1"
    local key_type="$2"

    # Skip if file doesn't exist or isn't readable
    [[ -f "$file" && -r "$file" ]] || return

    # Skip host keys
    if [[ "$file" == *"ssh_host_"* ]]; then
        warn "Skipping host key: $file"
        return
    fi

    # Verify it's actually a key file
    if ! is_key_file "$file"; then
        return
    fi

    ((KEYS_FOUND++))

    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run_msg "$file ($key_type)"
        return
    fi

    # Create encoded path for backup filename
    local encoded_path
    encoded_path=$(echo "$file" | sed 's|/|_|g' | sed 's|^_||')
    local backup_file="$LOG_DIR/${encoded_path}_${TIMESTAMP}.key"
    local meta_file="$LOG_DIR/${encoded_path}_${TIMESTAMP}.meta"

    # Backup the key
    cp "$file" "$backup_file" 2>/dev/null
    chmod 600 "$backup_file"

    # Save metadata
    {
        echo "Original Path: $file"
        echo "Key Type: $key_type"
        echo "Removal Date: $(date)"
        echo "Removed By: $(whoami)"
        echo ""
        echo "=== File Stats ==="
        stat "$file"
        echo ""
        echo "=== File Owner ==="
        ls -la "$file"
        echo ""
        echo "=== Key Fingerprint (if applicable) ==="
        ssh-keygen -lf "$file" 2>/dev/null || echo "Could not extract fingerprint"
    } > "$meta_file"
    chmod 600 "$meta_file"

    # Securely delete the file
    if command -v shred &>/dev/null; then
        shred -u "$file" 2>/dev/null
    else
        rm -f "$file"
    fi

    ((KEYS_REMOVED++))
    removed "$file -> Backed up to $backup_file"
}

process_user() {
    local user="$1"
    local home_dir

    # Get home directory
    home_dir=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [[ -d "$home_dir" ]] || return

    log "Processing user: $user ($home_dir)"

    # Process authorized_keys
    if [[ "$ONLY_PRIVATE" == "false" ]]; then
        local auth_paths
        auth_paths=$(get_authorized_keys_paths)

        for rel_path in $auth_paths; do
            # Handle %h (home directory) placeholder
            local full_path="${rel_path//%h/$home_dir}"

            # Handle ~ prefix
            if [[ "$full_path" == "~"* ]]; then
                full_path="$home_dir/${full_path#\~}"
                full_path="${full_path//\/\//\/}"  # Remove double slashes
            fi

            # If relative path, prepend home dir
            if [[ "$full_path" != /* ]]; then
                full_path="$home_dir/$full_path"
            fi

            backup_and_remove "$full_path" "authorized_keys"
        done
    fi

    # Process private keys
    if [[ "$ONLY_AUTHORIZED" == "false" ]]; then
        local private_key_names=("id_rsa" "id_dsa" "id_ecdsa" "id_ed25519" "id_xmss")

        for key_name in "${private_key_names[@]}"; do
            backup_and_remove "$home_dir/.ssh/$key_name" "private_key"
        done

        # Also check for any other potential private keys
        if [[ -d "$home_dir/.ssh" ]]; then
            find "$home_dir/.ssh" -type f -name "*.pem" 2>/dev/null | while read -r pem_file; do
                backup_and_remove "$pem_file" "private_key_pem"
            done

            find "$home_dir/.ssh" -type f -name "id_*" 2>/dev/null | grep -v ".pub$" | while read -r key_file; do
                backup_and_remove "$key_file" "private_key_other"
            done
        fi
    fi
}

# --- Main Execution ---
check_root

echo "========================================"
echo "SSH KEY PURGE - $(hostname)"
echo "Time: $(date)"
echo "========================================"

# Show what we're doing
if [[ "$ONLY_AUTHORIZED" == "true" ]]; then
    log "Mode: Authorized keys only"
elif [[ "$ONLY_PRIVATE" == "true" ]]; then
    log "Mode: Private keys only"
else
    log "Mode: All SSH keys"
fi

if [[ -n "$SPECIFIC_USER" ]]; then
    log "Target user: $SPECIFIC_USER"
else
    log "Target: All users with login shells"
fi

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${BLUE}>>> DRY RUN MODE - No files will be removed <<<${NC}"
fi

# Confirmation
if [[ "$DRY_RUN" == "false" && "$FORCE" == "false" ]]; then
    echo ""
    echo -e "${YELLOW}WARNING: This will remove SSH keys from the system.${NC}"
    echo -e "${YELLOW}Keys will be backed up to: $LOG_DIR${NC}"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted."
        exit 2
    fi
fi

# Setup log directory
if [[ "$DRY_RUN" == "false" ]]; then
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    log "Backup directory: $LOG_DIR"
fi

echo ""

# Process each user
for user in $(get_users); do
    process_user "$user"
done

# Also process root separately if not already included
if [[ -z "$SPECIFIC_USER" ]]; then
    # Check if root was already processed
    if ! get_users | grep -q "^root$"; then
        process_user "root"
    fi
fi

# Summary
echo ""
echo "========================================"
echo "SSH KEY PURGE COMPLETE"
echo "========================================"
echo "Keys found:   $KEYS_FOUND"

if [[ "$DRY_RUN" == "true" ]]; then
    echo "Keys removed: 0 (dry run)"
else
    echo "Keys removed: $KEYS_REMOVED"
    echo ""
    echo "Backups stored in: $LOG_DIR"

    if [[ $KEYS_REMOVED -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}IMPORTANT: SSH key-based authentication is now disabled.${NC}"
        echo -e "${YELLOW}Ensure password authentication is enabled or you may lose access!${NC}"
    fi
fi
echo "========================================"

exit 0
