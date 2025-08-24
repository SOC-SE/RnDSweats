#!/bin/bash

# Get the file path from the alert
FILE_PATH=$(echo "$3" | jq -r .parameters.alert.syscheck.path)

# Yara binary path
YARA_BIN="/usr/bin/yara"

# Yara rules path
YARA_RULES="/var/ossec/etc/yara/rules/production.yar" # Change to your rules file or a directory

# Log file for Yara scan results
LOG_FILE="/var/ossec/logs/active-responses.log"

# Run the Yara scan
$YARA_BIN -r $YARA_RULES "$FILE_PATH" >> $LOG_FILE
