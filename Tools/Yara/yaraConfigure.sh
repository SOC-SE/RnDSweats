#!/bin/bash

# CCDC Development - LMD Yara Rules Updater
# This script downloads the signature-base Yara rules, validates each one
# using the 'yara' CLI, and combines the *valid* rules into a master file for LMD.
# Run as root or with sudo.
 
# Removing set -e and -o pipefail to ensure the script runs completely
# set -e
# set -o pipefail

# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
YARA_RULES_SRC_DIR="${CLONE_DIR}/yara"
# LMD's file for all custom user Yara rules
LMD_USER_RULES_FILE="/usr/local/maldetect/sigs/user.yara"
LOG_FILE="/var/log/lmd_yara_updater.log"
BAD_RULE_LOG_FILE="/var/log/lmd_yara_bad_rules.log"

# --- Functions ---

# Function to print messages and log them
log() {
    echo "[*] $1" | tee -a "$LOG_FILE"
}

# Function to check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
       log "This script must be run as root. Aborting."
       exit 1
    fi
    log "Root privileges confirmed."
}

# Function to check for dependencies
check_deps() {
    local missing_deps=0
    # We now explicitly need 'yara'
    for cmd in git find xargs cat yara; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR: Dependency '$cmd' not found."
            missing_deps=1
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log "Please install the missing dependencies and run the script again."
        exit 1
    fi
    log "All dependencies are satisfied."
}

# Function to install dependencies
install_deps() {
    log "Installing Yara (needed by LMD and this script)..."
    if command -v apt-get &> /dev/null; then
        apt-get update -y > /dev/null 2>&1
        apt-get install yara -y
        
    elif command -v dnf &> /dev/null; then
        dnf install yara -y
        
    elif command -v yum &> /dev/null; then
        yum install yara -y
        
    else
        echo "Unsupported package manager. Please install Yara manually."
        exit 1
    fi
    echo "Yara installed successfully."
}

# Function to download the Yara rules
download_rules() {
    log "Downloading Yara rules from ${REPO_URL}..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
    log "Rules downloaded successfully to ${CLONE_DIR}."
}

# Function to build the master rule file by validating each rule
build_and_validate_rules() {
    log "Starting rule-by-rule validation... This may take a few minutes."
    
    # Clear old files
    rm -f "$LMD_USER_RULES_FILE"
    rm -f "$BAD_RULE_LOG_FILE"
    touch "$LMD_USER_RULES_FILE"
    
    local total_files=0
    local total_added=0
    local total_skipped=0

    # Find all rule files
    local all_rule_files=()
    mapfile -t all_rule_files < <(find "$YARA_RULES_SRC_DIR" -type f \( -name "*.yar" -o -name "*.yara" \))

    # Loop through each file
    for rule_file in "${all_rule_files[@]}"; do
        ((total_files++))
        
        # This is the test. We run the 'yara' command-line tool, providing
        # the dummy variables that were causing our syntax errors.
        if yara -w \
            -d filename="dummy" \
            -d filepath="dummy" \
            -d extension="dummy" \
            -d filetype="dummy" \
            -d filesize=0 \
            "$rule_file" /dev/null &> /dev/null; then
            
            # --- SUCCESS ---
            # The rule is valid, append it to the master file
            cat "$rule_file" >> "$LMD_USER_RULES_FILE"
            # Add a newline for safety
            echo -e "\n" >> "$LMD_USER_RULES_FILE"
            ((total_added++))
        else
            # --- FAILURE ---
            # The rule is invalid, log it and skip
            local rule_name=$(basename "$rule_file")
            log "  - SKIPPED: $rule_name (syntax error)"
            echo "SKIPPED: $rule_name" >> "$BAD_RULE_LOG_FILE"
            ((total_skipped++))
        fi
        
        # Print progress
        if ! ((total_files % 100)); then
            log "  ... processed $total_files files"
        fi
    done

    log "--- Validation Complete ---"
    log "Total Files Found:   $total_files"
    log "Total Rules ADDED:   $total_added"
    log "Total Rules SKIPPED: $total_skipped"
    log "-----------------------------"

    if [[ ! -s "$LMD_USER_RULES_FILE" ]]; then
        log "ERROR: The master rules file is empty. All rules may have failed."
        exit 1
    fi

    # Set standard permissions
    chmod 644 "$LMD_USER_RULES_FILE"

    log "Master rule file created successfully at ${LMD_USER_RULES_FILE}."
    log "A log of skipped bad rules is at ${BAD_RULE_LOG_FILE}."
}

# Function to cleanup temporary files
cleanup() {
    log "Cleaning up temporary build files..."
    rm -rf "$CLONE_DIR"
    log "Cleanup complete."
}

# --- Main Execution ---
main() {
    # Initialize log file for this run
    echo "--- LMD Yara Rules Updater Log ---" > "$LOG_FILE"
    
    check_root
    install_deps
    check_deps
    download_rules
    build_and_validate_rules  # <-- This is the new, robust function
    cleanup

    log "--- LMD Yara Rules Update Complete ---"
}

main "$@"

