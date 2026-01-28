#!/bin/bash
# ==============================================================================
# Script Name: linpeasDeploy.sh
# Description: Download and run LinPEAS for system enumeration
#              Supports online download and offline/pre-staged modes
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./linpeasDeploy.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -o, --output     Output file for results (default: /tmp/linpeas_output.txt)
#   -l, --local      Path to pre-staged linpeas.sh (offline mode)
#   -q, --quiet      Run LinPEAS in quiet mode (less output)
#   -f, --fast       Run LinPEAS in fast mode (skip slow checks)
#   -s, --stealth    Run LinPEAS in stealth mode (minimal footprint)
#   -a, --all        Run all LinPEAS checks (thorough mode)
#   -k, --keep       Keep downloaded linpeas.sh after execution
#   -n, --no-run     Download only, don't execute
#
# What LinPEAS Checks:
#   - System information and kernel exploits
#   - User and group enumeration
#   - Interesting files and permissions
#   - Network information
#   - Running processes and services
#   - Cron jobs and timers
#   - SUID/SGID binaries
#   - Capabilities
#   - Container detection
#   - And much more...
#
# Supported Systems:
#   - Ubuntu/Debian
#   - Fedora/RHEL/CentOS
#   - Alpine Linux
#   - Most Linux distributions
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - Download failed
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
LINPEAS_BACKUP_URL="https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/linpeas.sh"
OUTPUT_FILE="/tmp/linpeas_output_$(date +%Y%m%d_%H%M%S).txt"
LOCAL_LINPEAS=""
LINPEAS_ARGS=""
KEEP_FILE=false
NO_RUN=false
TEMP_DIR="/tmp"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Helper Functions ---
usage() {
    head -45 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    if [[ "$KEEP_FILE" == "false" && -f "$TEMP_DIR/linpeas.sh" ]]; then
        rm -f "$TEMP_DIR/linpeas.sh" 2>/dev/null
        log "Cleaned up temporary linpeas.sh"
    fi
}

trap cleanup EXIT

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -l|--local)
            LOCAL_LINPEAS="$2"
            shift 2
            ;;
        -q|--quiet)
            LINPEAS_ARGS="$LINPEAS_ARGS -q"
            shift
            ;;
        -f|--fast)
            LINPEAS_ARGS="$LINPEAS_ARGS -f"
            shift
            ;;
        -s|--stealth)
            LINPEAS_ARGS="$LINPEAS_ARGS -s"
            shift
            ;;
        -a|--all)
            LINPEAS_ARGS="$LINPEAS_ARGS -a"
            shift
            ;;
        -k|--keep)
            KEEP_FILE=true
            shift
            ;;
        -n|--no-run)
            NO_RUN=true
            KEEP_FILE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---
echo "========================================"
echo "LINPEAS DEPLOYER"
echo "Time: $(date)"
echo "========================================"
echo ""

LINPEAS_PATH=""

# Check for local/pre-staged LinPEAS
if [[ -n "$LOCAL_LINPEAS" ]]; then
    if [[ -f "$LOCAL_LINPEAS" ]]; then
        log "Using local LinPEAS: $LOCAL_LINPEAS"
        LINPEAS_PATH="$LOCAL_LINPEAS"
    else
        error "Local LinPEAS not found: $LOCAL_LINPEAS"
        exit 1
    fi
else
    # Download LinPEAS
    log "Downloading LinPEAS..."

    # Try curl first
    if command -v curl &>/dev/null; then
        if curl -sL "$LINPEAS_URL" -o "$TEMP_DIR/linpeas.sh" 2>/dev/null; then
            log "Downloaded via curl from releases"
            LINPEAS_PATH="$TEMP_DIR/linpeas.sh"
        elif curl -sL "$LINPEAS_BACKUP_URL" -o "$TEMP_DIR/linpeas.sh" 2>/dev/null; then
            log "Downloaded via curl from raw"
            LINPEAS_PATH="$TEMP_DIR/linpeas.sh"
        fi
    fi

    # Try wget if curl failed
    if [[ -z "$LINPEAS_PATH" ]] && command -v wget &>/dev/null; then
        if wget -q "$LINPEAS_URL" -O "$TEMP_DIR/linpeas.sh" 2>/dev/null; then
            log "Downloaded via wget from releases"
            LINPEAS_PATH="$TEMP_DIR/linpeas.sh"
        elif wget -q "$LINPEAS_BACKUP_URL" -O "$TEMP_DIR/linpeas.sh" 2>/dev/null; then
            log "Downloaded via wget from raw"
            LINPEAS_PATH="$TEMP_DIR/linpeas.sh"
        fi
    fi

    # Check if download was successful
    if [[ -z "$LINPEAS_PATH" || ! -s "$LINPEAS_PATH" ]]; then
        error "Failed to download LinPEAS"
        error "Check internet connectivity or use --local with a pre-staged file"
        echo ""
        echo "To pre-stage LinPEAS:"
        echo "  curl -L $LINPEAS_URL -o linpeas.sh"
        echo "  Then run: $0 --local linpeas.sh"
        exit 2
    fi
fi

# Make executable
chmod +x "$LINPEAS_PATH"

# Verify it's a valid script
if ! head -1 "$LINPEAS_PATH" | grep -qE "^#!"; then
    error "Downloaded file doesn't appear to be a valid script"
    exit 1
fi

# Get file size for verification
file_size=$(stat -f%z "$LINPEAS_PATH" 2>/dev/null || stat -c%s "$LINPEAS_PATH" 2>/dev/null)
log "LinPEAS size: $((file_size / 1024)) KB"

if [[ "$NO_RUN" == "true" ]]; then
    log "Download complete. LinPEAS saved to: $LINPEAS_PATH"
    echo ""
    echo "To run manually:"
    echo "  bash $LINPEAS_PATH | tee $OUTPUT_FILE"
    exit 0
fi

# Run LinPEAS
echo ""
log "Running LinPEAS..."
log "Output will be saved to: $OUTPUT_FILE"
log "LinPEAS arguments: ${LINPEAS_ARGS:-none}"
echo ""
echo "========================================"
echo "LINPEAS OUTPUT BEGINS"
echo "========================================"
echo ""

# Run with tee to capture output
# shellcheck disable=SC2086
bash "$LINPEAS_PATH" $LINPEAS_ARGS 2>&1 | tee "$OUTPUT_FILE"

echo ""
echo "========================================"
echo "LINPEAS COMPLETE"
echo "========================================"
echo ""
echo "Output saved to: $OUTPUT_FILE"
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo ""
echo "Quick analysis tips:"
echo "  - Look for RED/YELLOW highlighted items"
echo "  - Check 'Interesting Files' section for credentials"
echo "  - Review 'SUID' section for privilege escalation"
echo "  - Check 'Processes' for sensitive information"
echo ""
echo "To view output with colors:"
echo "  less -R $OUTPUT_FILE"
echo ""
echo "To search for specific patterns:"
echo "  grep -i 'password' $OUTPUT_FILE"
echo "  grep -i 'key' $OUTPUT_FILE"
echo "  grep -i 'credential' $OUTPUT_FILE"
echo "========================================"

exit 0
