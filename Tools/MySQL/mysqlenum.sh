#!/bin/bash
set -euo pipefail

CNF_FILE="$HOME/.my.cnf"
OUTPUT_FILE="$(dirname "$0")/mysql_audit_report.txt"

if [ ! -f "$CNF_FILE" ]; then
    echo "Error: Configuration file $CNF_FILE not found."
    echo "Please run the backup script setup first to generate credentials."
    exit 1
fi

{
    echo "========================================================"
    echo "MYSQL INSTANCE AUDIT REPORT"
    echo "Date: $(date)"
    echo "========================================================"
    echo ""

    echo "--- EXISTING DATABASES ---"
    mysql --defaults-extra-file="$CNF_FILE" -t -e "SHOW DATABASES;"

    echo ""
    echo "--- USERS AND PERMISSIONS ---"

    USER_LIST=$(mysql --defaults-extra-file="$CNF_FILE" -N -e "SELECT CONCAT('\'', User, '\'@\'', Host, '\'') FROM mysql.user")

    while IFS= read -r user; do
        echo "User: $user"
        
        if [[ "$user" == *"''@"* ]]; then
            echo "(Note: This is an ANONYMOUS user)"
        fi

        echo "Grants:"

        mysql --defaults-extra-file="$CNF_FILE" -N -e "SHOW GRANTS FOR $user;" 2>&1 | sed 's/^/  /' 
        
        echo "--------------------------------------------------------"
    done <<< "$USER_LIST"

    echo "Audit complete."

} > "$OUTPUT_FILE"

echo -e "Enumeration log found at $OUTPUT_FILE"