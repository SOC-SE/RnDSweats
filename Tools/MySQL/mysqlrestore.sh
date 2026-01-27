#!/bin/bash
#
# MySQL Full Restore Script
# Restores all databases from a compressed backup file
#
# Usage: sudo ./mysqlrestore.sh /path/to/backup_file.sql.gz
#
set -euo pipefail

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

# --- ARGUMENT VALIDATION ---
if [[ -z "${1:-}" ]]; then
    echo "Usage: $0 /path/to/backup_file.sql.gz"
    exit 1
fi

BACKUP_FILE="$1"

# --- VALIDATE BACKUP FILE ---
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Error: Backup file not found: $BACKUP_FILE" >&2
    exit 1
fi

if [[ ! -r "$BACKUP_FILE" ]]; then
    echo "Error: Cannot read backup file: $BACKUP_FILE" >&2
    exit 1
fi

# --- CHECK CREDENTIALS FILE ---
CNF_FILE="$HOME/.my.cnf"
if [[ ! -f "$CNF_FILE" ]]; then
    echo "Error: MySQL credentials file not found: $CNF_FILE" >&2
    echo "Please run mysqlbackup.sh first to create credentials, or create manually:" >&2
    echo "  [client]" >&2
    echo "  user=root" >&2
    echo "  password=YOUR_PASSWORD" >&2
    exit 1
fi
echo "WARNING: ONLY USE IN CASE OF MAXIMUM DB FAILURE. THIS COULD KILL THE BOX."
echo "WARNING: This will overwrite the ENTIRE MySQL instance."
echo "Any databases or tables created AFTER this backup will be DELETED permanently."
read -r -p "Are you sure you want to proceed? (type 'yes' to confirm): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo "Starting restoration process..."

echo "Dropping existing user databases to ensure a clean slate..."

# Get list of user databases (excluding system databases)
while IFS= read -r db; do
    [[ -z "$db" ]] && continue
    echo "Dropping database: $db"
    mysql --defaults-extra-file="$CNF_FILE" -e "DROP DATABASE IF EXISTS \`$db\`;"
done < <(mysql --defaults-extra-file="$CNF_FILE" -Bse "SHOW DATABASES;" | grep -vE "^(information_schema|performance_schema|mysql|sys)$")

echo "Importing data from $BACKUP_FILE..."

if zcat "$BACKUP_FILE" | sed -e 's/^LOCK TABLES/-- LOCK TABLES/g' | mysql --defaults-extra-file="$CNF_FILE" -f; then
    echo "Data import complete (System table errors were ignored safely)."

    echo "Flushing privileges..."
    mysql --defaults-extra-file="$CNF_FILE" -e "FLUSH PRIVILEGES;"

    echo "Restore finished successfully."
else
    echo "Critical Restore failure."
    exit 1
fi
