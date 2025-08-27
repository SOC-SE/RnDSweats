#!/bin/bash

# CCDC Development - Centralized Yara Rules Compiler
# This script downloads the signature-base Yara rules, removes problematic ones,
# and compiles them into a centralized location (/opt/yara-rules).
# This allows Wazuh and other tools to use the same compiled ruleset.
# Run as root or with sudo.
 
set -e
set -o pipefail

# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
# Centralized location for storing compiled Yara rules
RULES_STORAGE_DIR="/opt/yara-rules"
COMPILED_RULES_FILE="compiled_community_rules.yarac"
LOG_FILE="/var/log/yara_rules_compiler.log"
MASTER_RULES_FILE_TMP="${CLONE_DIR}/master.yar"
EXCLUDED_RULES_LOG="${CLONE_DIR}/excluded_rules.log"

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
    for cmd in git yarac awk grep sed; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR: Dependency '$cmd' not found."
            missing_deps=1
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log "Please install the missing dependencies and run the script again."
        log "Hint: 'yarac' is part of the Yara package. You may need to compile it from source."
        exit 1
    fi
    log "All dependencies are satisfied."
}

# Function to download the Yara rules
download_rules() {
    log "Downloading Yara rules from ${REPO_URL}..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
    log "Rules downloaded successfully to ${CLONE_DIR}."
}

# Function to assemble and filter the rules
process_rules() {
    log "Identifying rules to exclude..."
    # Add any other rule files you want to completely exclude to this list
    declare -a files_to_exclude=(
        "${CLONE_DIR}/yara/expl_connectwise_screenconnect_vuln_feb24.yar"
        "${CLONE_DIR}/yara/thor_inverse_matches.yar"
    )

    # Use a temporary file to store the names of rules to be excluded
    local temp_rules_to_exclude
    temp_rules_to_exclude=$(mktemp)

    for file in "${files_to_exclude[@]}"; do
        if [ -f "$file" ]; then
            # Extract the rule names from the files marked for exclusion
            grep -oP '^\s*rule\s+\K\w+' "$file" >> "$temp_rules_to_exclude"
        fi
    done

    log "Assembling all .yar/.yara files into a master file..."
    find "$CLONE_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 | xargs -0 cat > "$MASTER_RULES_FILE_TMP"

    if [[ ! -s "$MASTER_RULES_FILE_TMP" ]]; then
        log "ERROR: The master rules file ('$MASTER_RULES_FILE_TMP') is empty after attempting to assemble the rules."
        log "This usually means that the git clone failed or that the repository structure has changed and no .yar/.yara files were found."
        log "Please check the clone directory ('$CLONE_DIR') to investigate."
        exit 1
    fi

    log "Filtering master rules file in a single pass..."
    local temp_master_filtered
    temp_master_filtered=$(mktemp)

    echo "--- Excluded Rules ---" > "$EXCLUDED_RULES_LOG"
    awk -v log_file="$EXCLUDED_RULES_LOG" '
        NR==FNR { rules_to_exclude[$1] = 1; next }
        in_excluded_block { if (/^}/) { in_excluded_block = 0 }; next }
        $1 == "rule" && ($2 in rules_to_exclude) { in_excluded_block = 1; print "/* Rule \047" $2 "\047 excluded */"; print $2 >> log_file; next }
        { print }
    ' "$temp_rules_to_exclude" "$MASTER_RULES_FILE_TMP" > "$temp_master_filtered"

    mv "$temp_master_filtered" "$MASTER_RULES_FILE_TMP"
    log "A log of all excluded rules has been saved to ${EXCLUDED_RULES_LOG}."
    rm "$temp_rules_to_exclude"
}

# Function to compile the rules
compile_rules() {
    log "Compiling the final ruleset..."
    # The -w flag disables common (and noisy) warnings from this community repo
    yarac -w -o "${CLONE_DIR}/${COMPILED_RULES_FILE}" "$MASTER_RULES_FILE_TMP"
    log "Rules compiled successfully."
}

# Function to deploy the compiled rules
deploy_rules() {
    log "Deploying compiled rules to ${RULES_STORAGE_DIR}..."
    mkdir -p "$RULES_STORAGE_DIR"
    mv "${CLONE_DIR}/${COMPILED_RULES_FILE}" "${RULES_STORAGE_DIR}/${COMPILED_RULES_FILE}"
    
    # Set appropriate permissions for Wazuh (user: wazuh) to read the files
    # Modern Wazuh runs as the 'wazuh' user/group.
    chown -R root:wazuh "$RULES_STORAGE_DIR"
    chmod 750 "$RULES_STORAGE_DIR"
    chmod 640 "${RULES_STORAGE_DIR}/${COMPILED_RULES_FILE}"
    
    log "Deployment complete."
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
    echo "--- Yara Rules Compiler Log ---" > "$LOG_FILE"
    
    check_root
    check_deps
    download_rules
    process_rules
    compile_rules
    deploy_rules
    cleanup

    log "--- Yara Rules Update Complete ---"
}

main "$@"