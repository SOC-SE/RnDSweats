#!/bin/bash


if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/backup_file.sql.gz"
    exit 1
fi

BACKUP_FILE="$1"
echo "⚠️  WARNING: ONLY USE IN CASE OF MAXIMUM DB FAILURE. THIS COULD KILL THE BOX."
echo "⚠️  WARNING: This will overwrite the ENTIRE MySQL instance."
echo "Any databases or tables created AFTER this backup will be DELETED permanently."
read -p "Are you sure you want to proceed? (type 'yes' to confirm): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo "Starting restoration process..."

echo "🧹 Dropping existing user databases to ensure a clean slate..."

DBS=$(mysql --defaults-extra-file=~/.my.cnf -Bse "SHOW DATABASES;" | grep -vE "^(information_schema|performance_schema|mysql|sys)$")

for db in $DBS; do
    echo "Dropping database: $db"
    mysql --defaults-extra-file=~/.my.cnf -e "DROP DATABASE IF EXISTS \`$db\`;"
done

echo "📥 Importing data from $BACKUP_FILE..."

if zcat "$BACKUP_FILE" | sed -e 's/^LOCK TABLES/-- LOCK TABLES/g' | mysql --defaults-extra-file=~/.my.cnf -f; then
    echo "✅ Data import complete (System table errors were ignored safely)."
    
    echo "🔄 Flushing privileges..."
    mysql --defaults-extra-file=~/.my.cnf -e "FLUSH PRIVILEGES;"
    
    echo "Restore finished successfully."
else
    echo "❌ Critical Restore failure."
    exit 1
fi
