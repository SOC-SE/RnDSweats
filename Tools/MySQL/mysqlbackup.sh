#!/bin/bash

# --- CONFIGURATION ---
BACKUP_DIR="/var/backups/mysql"
DATE=$(date +%F_%H-%M-%S)
BACKUP_FILE="$BACKUP_DIR/full_backup_$DATE.sql.gz"
CNF_FILE="$HOME/.my.cnf"
RETENTION_DAYS=7

if [ ! -f "$CNF_FILE" ]; then
    echo "⚠️  Configuration file not found."
    echo "Please enter the credentials to create $CNF_FILE"
    
    read -p "Enter MySQL Username (e.g., root): " DB_USER

    read -s -p "Enter MySQL Password: " DB_PASS

    echo "[client]" > "$CNF_FILE"
    echo "user=$DB_USER" >> "$CNF_FILE"
    echo "password=$DB_PASS" >> "$CNF_FILE"


    chmod 600 "$CNF_FILE"
    echo "✅ Created $CNF_FILE with secure permissions."
else
    echo "ℹ️  Using existing credentials found in $CNF_FILE"
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

if [ $? -eq 0 ]; then
    echo "✅ Backup successful: $BACKUP_FILE"
else
    echo "❌ Backup failed!"
    exit 1
fi