#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script as root (e.g., sudo ./setup_postscreen.sh)"
  exit 1
fi

POSTFIX_DIR="/etc/postfix"
MASTER_CF="$POSTFIX_DIR/master.cf"
MAIN_CF="$POSTFIX_DIR/main.cf"

backup_and_configure() {
    echo ""
    echo "--- Step 1: Creating Backups ---"
    TIMESTAMP=$(date +%F_%H-%M-%S)
    
    if cp "$MASTER_CF" "${MASTER_CF}.pre_postscreen_${TIMESTAMP}" && cp "$MAIN_CF" "${MAIN_CF}.pre_postscreen_${TIMESTAMP}"; then
        echo "Success: Backups created with suffix 'pre_postscreen_${TIMESTAMP}'"
    else
        echo "Error: Failed to create backups. Aborting configuration."
        exit 1
    fi

    echo ""
    echo "--- Step 2: Configuring master.cf ---"
    # Comment out the default smtpd line on port 25
    sed -i 's/^smtp\s\+inet\s\+n\s\+-\s\+n\s\+-\s\+-\s\+smtpd/#smtp      inet  n       -       n       -       -       smtpd/' "$MASTER_CF"
    
    # Check for an ACTIVE postscreen line (starts with smtp, not #smtp)
    if ! grep -q "^smtp.*inet.*postscreen" "$MASTER_CF"; then
        cat << 'EOF' >> "$MASTER_CF"

# --- POSTSCREEN ENABLEMENT ---
smtp      inet  n       -       n       -       1       postscreen
smtpd     pass  -       -       n       -       -       smtpd
dnsblog   unix  -       -       n       -       0       dnsblog
tlsproxy  unix  -       -       n       -       0       tlsproxy
EOF
        echo "Success: Injected Postscreen daemons into master.cf"
    else
        echo "Notice: Active Postscreen definitions already exist in master.cf. Skipping injection."
    fi

    echo ""
    echo "--- Step 3: Configuring main.cf ---"
    # Append Postscreen rules to main.cf if they don't already exist
    if ! grep -q "postscreen_greet_action" "$MAIN_CF"; then
        cat << 'EOF' >> "$MAIN_CF"

# --- POSTSCREEN SETTINGS ---
postscreen_greet_action = enforce
postscreen_dnsbl_action = enforce
postscreen_dnsbl_threshold = 3
postscreen_dnsbl_sites = zen.spamhaus.org*3, b.barracudacentral.org*2, bl.spameatingmonkey.net*2
postscreen_bare_newline_action = enforce
postscreen_non_smtp_command_action = enforce
postscreen_pipelining_action = enforce
EOF
        echo "Success: Injected Postscreen settings into main.cf"
    else
        echo "Notice: Postscreen settings already exist in main.cf. Skipping injection."
    fi

    echo ""
    echo "--- Step 4: Reloading Postfix ---"
    systemctl reload postfix
    echo "Done: Postscreen configuration complete and service reloaded!"
    echo ""
}

revert_config() {
    echo ""
    echo "--- Initiating Emergency Revert ---"
    
    # Find the most recent backup files
    LATEST_MASTER_BAK=$(ls -t "${MASTER_CF}.pre_postscreen_"* 2>/dev/null | head -1)
    LATEST_MAIN_BAK=$(ls -t "${MAIN_CF}.pre_postscreen_"* 2>/dev/null | head -1)

    if [[ -z "$LATEST_MASTER_BAK" || -z "$LATEST_MAIN_BAK" ]]; then
        echo "Error: No Postscreen backups found in $POSTFIX_DIR!"
        echo ""
        return
    fi

    echo "Restoring master.cf from: $(basename "$LATEST_MASTER_BAK")"
    cp "$LATEST_MASTER_BAK" "$MASTER_CF"
    
    echo "Restoring main.cf from: $(basename "$LATEST_MAIN_BAK")"
    cp "$LATEST_MAIN_BAK" "$MAIN_CF"

    echo "Reloading Postfix..."
    systemctl reload postfix
    echo "Done: Revert complete. Postfix has been restored to its previous state."
    echo ""
}

# --- Main Interactive Menu ---
clear
echo "================================================="
echo "  Postfix Postscreen Setup & Rollback Utility "
echo "================================================="
echo ""

PS3="Select an option (1-3): "
options=("Backup and Enable Postscreen" "Emergency Revert" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Backup and Enable Postscreen")
            backup_and_configure
            break
            ;;
        "Emergency Revert")
            revert_config
            break
            ;;
        "Quit")
            echo "Exiting. No changes made."
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done