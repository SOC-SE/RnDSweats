#!/usr/bin/env bash

# Get the current admin's session info so we don't accidentally kill ourselves
ADMIN_USER=$(whoami)
ADMIN_SESSION=$(tty | cut -d"/" -f3-)

# Function to check sessions for a specific user
check_user_sessions() {
    local TARGET_USER=$1
    
    # Find all sessions for this user
    # We filter out the ADMIN_SESSION to ensure we never kill the script's own terminal
    local ALLSESS=$(w -h "$TARGET_USER" | grep "^$TARGET_USER" | grep -v "$ADMIN_SESSION" | tr -s " " | cut -d" " -f2)
    
    # If sessions exist
    if [[ ! -z "$ALLSESS" ]]; then
        echo "------------------------------------------------------------------"
        printf "\e[33mActive sessions for user: $TARGET_USER\e[0m\n"
        
        # Display detailed session info
        w "$TARGET_USER" | grep "^$TARGET_USER" | grep -v "$ADMIN_SESSION" | column -t
        echo "------------------------------------------------------------------"
        
        # Interactive Prompt
        read -p "Force close all sessions for $TARGET_USER? [Y]Yes/[N]No: " answer
        answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')
        
        if [[ "$answer" == "y" || "$answer" == "yes" ]]; then
            for SESSION in $ALLSESS; do
                # Double check we aren't killing ourself (redundant safety)
                if [[ "$SESSION" != "$ADMIN_SESSION" ]]; then
                    pkill -9 -t "$SESSION"
                    echo "Session $SESSION closed."
                fi
            done
        else
            echo "Skipping $TARGET_USER."
        fi
        echo ""
    fi
}

# 1. Identify Valid Shells (Filters out /bin/false, /sbin/nologin, etc.)
# We grab all shells listed in /etc/shells
VALID_SHELLS=$(grep -v "^#" /etc/shells | tr '\n' '|')
VALID_SHELLS=${VALID_SHELLS%|} # Remove trailing pipe

# 2. Get list of users who use those shells
# We scan /etc/passwd and match the shell field ($7) against our valid list
USER_LIST=$(awk -F: -v shells="$VALID_SHELLS" '$7 ~ shells {print $1}' /etc/passwd)

echo "Scanning for active sessions..."

# 3. Iterate through every valid user
for u in $USER_LIST; do
    # Only run check if the user is actually logged in right now
    if w -h "$u" | grep -q "^$u"; then
        check_user_sessions "$u"
    fi
done

echo "Scan complete."