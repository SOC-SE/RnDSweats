# ==============================================================================
# File: Liaison/FIM.sh (Corrected)
# Description: Monitors file integrity in a specified directory using SHA256 hashes.
#              Generates a baseline and periodically checks for changes.
#
# Changes Made:
# 1. Aligned with "What Works.txt" by requiring a directory path argument.
# 2. Implemented a custom bash-based FIM using find and sha256sum for real-time monitoring.
# 3. Added a loop for continuous checking (every 60 seconds) that can be interrupted with Ctrl+C or pkill.
# 4. No package installation needed; uses built-in tools for portability in virtual environments.
# 5. Optimized for efficiency in VMs (e.g., avoids heavy tools like AIDE for targeted directory monitoring).
# 6. Added error handling for invalid directory and baseline creation.
# ==============================================================================

#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error.
# Fail on pipe errors.
set -euo pipefail

# --- Configuration & Colors ---
CHECK_INTERVAL=60  # Seconds between checks
BASELINE_FILE="fim_baseline.txt"
CURRENT_FILE="fim_current.txt"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Helper Functions ---
log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

# --- Validate Directory ---
validate_directory() {
    if [ -z "$1" ]; then
        log_error "Usage: $0 <directory_path>"
    fi
    if [ ! -d "$1" ]; then
        log_error "Directory '$1' does not exist."
    fi
    MONITOR_DIR=$(realpath "$1")
    log_info "Monitoring directory: $MONITOR_DIR"
}

# --- Generate Baseline ---
generate_baseline() {
    if [ -f "$BASELINE_FILE" ]; then
        log_warn "Baseline file already exists. Overwriting..."
    fi
    log_info "Generating baseline hash file..."
    find "$MONITOR_DIR" -type f -print0 | xargs -0 sha256sum > "$BASELINE_FILE"
    log_info "Baseline created: $BASELINE_FILE"
}

# --- Monitor Loop ---
monitor_changes() {
    log_info "Starting continuous monitoring. Press Ctrl+C to stop or use 'pkill -f FIM.sh' from another terminal."
    while true; do
        find "$MONITOR_DIR" -type f -print0 | xargs -0 sha256sum > "$CURRENT_FILE"
        if ! diff -q "$BASELINE_FILE" "$CURRENT_FILE" > /dev/null 2>&1; then
            log_warn "Changes detected!"
            diff "$BASELINE_FILE" "$CURRENT_FILE"
        else
            log_info "No changes detected."
        fi
        rm -f "$CURRENT_FILE"
        sleep "$CHECK_INTERVAL"
    done
}

# --- Main Logic ---
main() {
    # No root required for this custom FIM, as it uses standard user tools.
    validate_directory "$1"
    generate_baseline
    monitor_changes
}

main "$@"