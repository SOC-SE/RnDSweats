#!/bin/bash
#
# MySQL Full Backup Script
# Creates compressed backup of all databases with automatic retention cleanup
#
# Usage: sudo ./mysqlbackup.sh
#
set -euo pipefail

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

# --- CONFIGURATION ---
BACKUP_DIR="/var/backups/mysql"
DATE=$(date +%F_%H-%M-%S)
BACKUP_FILE="$BACKUP_DIR/full_backup_$DATE.sql.gz"
CNF_FILE="$HOME/.my.cnf"
RETENTION_DAYS=7

if [ ! -f "$CNF_FILE" ]; then
    echo "Configuration file not found."
    echo "Please enter the credentials to create $CNF_FILE"

    read -r -p "Enter MySQL Username (e.g., root): " DB_USER

    read -r -s -p "Enter MySQL Password: " DB_PASS
    echo

    echo "[client]" > "$CNF_FILE"
    echo "user=$DB_USER" >> "$CNF_FILE"
    echo "password=$DB_PASS" >> "$CNF_FILE"

    chmod 600 "$CNF_FILE"
    echo "Created $CNF_FILE with secure permissions."
else
    echo "Using existing credentials found in $CNF_FILE"
fi

mkdir -p "$BACKUP_DIR"

echo "Starting backup for all databases..."

mysqldump --defaults-extra-file="$CNF_FILE" \
    --all-databases \
    --add-drop-database \
    --add-drop-table \
    --routines \
    --events \
    --triggers \
    --single-transaction \
    --skip-add-locks \
    --set-gtid-purged=OFF \
    | gzip > "$BACKUP_FILE"

if [[ -f "$BACKUP_FILE" && -s "$BACKUP_FILE" ]]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup successful: $BACKUP_FILE ($BACKUP_SIZE)"
else
    echo "Backup failed!"
    exit 1
fi

# Retention cleanup - remove backups older than RETENTION_DAYS
echo "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "full_backup_*.sql.gz" -type f -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
echo "Cleanup complete"
