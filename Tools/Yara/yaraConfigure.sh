#!/bin/bash

# CCDC Development - LMD Yara Rules Updater
# This script is now a wrapper. It prepares the environment and then
# executes the python script 'build_lmd_rules.py' to safely
# build the LMD user.yara file.
# Run as root or with sudo.
 
# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
BUILD_SCRIPT_NAME="build_lmd_rules.py"
LOG_FILE="/var/log/lmd_yara_updater.log"

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

# Function to install dependencies
install_deps() {
    log "Installing dependencies (git, python3, pip, yara)..."
    if command -v apt-get &> /dev/null; then
        apt-get update -y > /dev/null 2>&1
        apt-get install -y git python3 python3-pip yara
    elif command -v dnf &> /dev/null; then
        dnf install -y git python3 python3-pip yara
    elif command -v yum &> /dev/null; then
        yum install -y git python3 python3-pip yara
    else
        log "ERROR: Unsupported package manager. Please install git, python3, python3-pip, and yara."
        exit 1
    fi
    
    log "Installing yara-python library..."
    # Use pip3 to install the required python module
    pip3 install --break-system-packages yara-python
    
    log "Dependencies installed successfully."
}

# Function to download the Yara rules
download_rules() {
    log "Downloading Yara rules from ${REPO_URL}..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
    log "Rules downloaded successfully to ${CLONE_DIR}."
}

# Function to copy our new build script into the repo
place_build_script() {
    log "Placing our custom build script into the repo directory..."
    # This assumes build_lmd_rules.py is in the same directory as this bash script
    # We copy it into the clone directory to give it access to the 'yara' folder
    cp ./$BUILD_SCRIPT_NAME $CLONE_DIR/
    chmod +x $CLONE_DIR/$BUILD_SCRIPT_NAME
}

# Function to run the python build script
build_rules() {
    log "Running the python build script..."
    cd $CLONE_DIR
    # Execute the python script. It will handle the rest.
    python3 ./$BUILD_SCRIPT_NAME
    cd -
    log "Python build script finished."
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
    download_rules
    place_build_script
    build_rules
    cleanup

    log "--- LMD Yara Rules Update Complete ---"
    log "The new ruleset is at /usr/local/maldetect/sigs/user.yara"
    log "A log of any skipped/bad rules is at /tmp/bad_rules.log"
}

main "$@"

