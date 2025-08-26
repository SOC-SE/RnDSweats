#!/bin/bash

#================================================================================
#
# Yara Scan Script for Wazuh
# Author: Gemini
# Last Modified: August 26, 2025
#
# Description:
#   This script performs a Yara scan on a specified directory or file.
#   It's designed to be triggered by Wazuh's active response to scan
#   new or modified files. The output is formatted for custom Wazuh decoders.
#
# Exit Codes:
#   0: Success (no matches or scan completed)
#   1: Error (wrong arguments, paths not found)
#
#================================================================================

#----------------------------------------------------
# Configuration - MODIFY THESE VARIABLES
#----------------------------------------------------
# Path to the Yara binary
YARA_EXEC="/usr/bin/yara"

# Path to your master Yara rules file (e.g., a single .yar file including all others)
YARA_RULES="/var/ossec/etc/yara/rules/production.yar"

# Log file where scan results will be written for Wazuh to read
LOG_FILE="/var/log/yara_scans.log"

#----------------------------------------------------
# Script Logic - DO NOT MODIFY BELOW THIS LINE
#----------------------------------------------------

# Check for correct number of arguments
if [ "$#" -ne 1 ]; then
    echo "ERROR: Incorrect usage. A file or directory path must be provided." >> "$LOG_FILE"
    exit 1
fi

TARGET_PATH=$1

# Ensure Yara executable and rules exist
if [ ! -x "$YARA_EXEC" ]; then
    echo "ERROR: Yara executable not found at $YARA_EXEC" >> "$LOG_FILE"
    exit 1
fi

if [ ! -f "$YARA_RULES" ]; then
    echo "ERROR: Yara rules file not found at $YARA_RULES" >> "$LOG_FILE"
    exit 1
fi

# Ensure the target path exists
if [ ! -e "$TARGET_PATH" ]; then
    echo "WARNING: Target path $TARGET_PATH does not exist. Scan skipped." >> "$LOG_FILE"
    exit 0 # Exit gracefully as the file may have been deleted
fi

# Run the Yara scan
# -w : Disable warnings
# -m : Print metadata along with the rule
# -s : Print rule strings
# The output is piped to awk to format it for our decoder
SCAN_OUTPUT=$($YARA_EXEC -w -m -s "$YARA_RULES" "$TARGET_PATH")

# Check if there was any output (i.e., a match)
if [ -n "$SCAN_OUTPUT" ]; then
    # Format and write the output to the log file for each match
    echo "$SCAN_OUTPUT" | while IFS= read -r line; do
        # Prepend our custom header for the Wazuh decoder to catch
        echo "YARA scan result: $line" >> "$LOG_FILE"
    done
fi

exit 0
