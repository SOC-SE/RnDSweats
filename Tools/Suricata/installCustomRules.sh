#!/bin/bash
# ==============================================================================
# Script Name: installCustomRules.sh
# Description: Install CCDC custom Suricata rules for PII detection,
#              data exfiltration monitoring, and C2 detection
# Author: CCDC Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./installCustomRules.sh [options]
#
# Options:
#   -h, --help       Show this help message
#   -t, --test       Test rules before installing
#   -r, --reload     Reload Suricata after install
#   -b, --backup     Backup existing rules first
#
# Prerequisites:
#   - Suricata must be installed
#   - Run after suricataSetup.sh
#
# Rules Included:
#   - PII Detection (SSN, Credit Cards, Emails, Phone Numbers)
#   - Credential Leakage (Passwords, API Keys, Private Keys)
#   - File Exfiltration (/etc/passwd, /etc/shadow, SAM)
#   - Reverse Shell Detection (Bash, Python, Perl, Netcat)
#   - Webshell Patterns (PHP eval, system, shell_exec)
#   - Cryptocurrency Mining Detection
#   - DNS Exfiltration
#
# Exit Codes:
#   0 - Success
#   1 - Error
#   2 - Suricata not installed
#
# ==============================================================================

set -uo pipefail

# --- Configuration ---
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SURICATA_RULES_DIR="/etc/suricata/rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
CUSTOM_RULES_FILE="$SCRIPT_DIR/ccdc-pii.rules"
TEST_ONLY=false
RELOAD_SURICATA=false
BACKUP_RULES=false

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -t|--test)
            TEST_ONLY=true
            shift
            ;;
        -r|--reload)
            RELOAD_SURICATA=true
            shift
            ;;
        -b|--backup)
            BACKUP_RULES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main ---
check_root

echo "========================================"
echo "CCDC Custom Suricata Rules Installer"
echo "Time: $(date)"
echo "========================================"
echo ""

# Check if Suricata is installed
if ! command -v suricata &>/dev/null; then
    error "Suricata is not installed"
    echo "Run suricataSetup.sh first to install Suricata"
    exit 2
fi

log "Suricata version: $(suricata --build-info | grep -i version | head -1)"

# Check if custom rules file exists
if [[ ! -f "$CUSTOM_RULES_FILE" ]]; then
    error "Custom rules file not found: $CUSTOM_RULES_FILE"
    exit 1
fi

# Create rules directory if it doesn't exist
if [[ ! -d "$SURICATA_RULES_DIR" ]]; then
    log "Creating rules directory: $SURICATA_RULES_DIR"
    mkdir -p "$SURICATA_RULES_DIR"
fi

# Backup existing rules if requested
if [[ "$BACKUP_RULES" == "true" && -f "$SURICATA_RULES_DIR/ccdc-pii.rules" ]]; then
    BACKUP_FILE="$SURICATA_RULES_DIR/ccdc-pii.rules.bak.$(date +%s)"
    cp "$SURICATA_RULES_DIR/ccdc-pii.rules" "$BACKUP_FILE"
    log "Backed up existing rules to: $BACKUP_FILE"
fi

# Copy rules file
log "Installing custom rules..."
cp "$CUSTOM_RULES_FILE" "$SURICATA_RULES_DIR/ccdc-pii.rules"
chmod 644 "$SURICATA_RULES_DIR/ccdc-pii.rules"
log "Installed: $SURICATA_RULES_DIR/ccdc-pii.rules"

# Count rules
RULE_COUNT=$(grep -cE "^alert" "$SURICATA_RULES_DIR/ccdc-pii.rules" || echo "0")
log "Total rules installed: $RULE_COUNT"

# Check if rules are already in suricata.yaml
if grep -q "ccdc-pii.rules" "$SURICATA_YAML" 2>/dev/null; then
    log "Rules already configured in suricata.yaml"
else
    log "Adding rules to suricata.yaml..."

    # Find the rule-files section and add our rules
    if grep -q "rule-files:" "$SURICATA_YAML"; then
        # Add after the rule-files: line
        sed -i '/^rule-files:/a\  - ccdc-pii.rules' "$SURICATA_YAML"
        log "Added ccdc-pii.rules to suricata.yaml"
    else
        warn "Could not find rule-files section in suricata.yaml"
        echo "Please add manually:"
        echo "  rule-files:"
        echo "    - ccdc-pii.rules"
    fi
fi

# Test configuration
log "Testing Suricata configuration..."
if suricata -T -c "$SURICATA_YAML" 2>&1 | tail -5; then
    echo ""
    log "Configuration test passed"
else
    error "Configuration test failed!"
    echo "Check the rules for syntax errors"
    exit 1
fi

if [[ "$TEST_ONLY" == "true" ]]; then
    log "Test mode - no changes applied to running Suricata"
    exit 0
fi

# Reload Suricata if requested
if [[ "$RELOAD_SURICATA" == "true" ]]; then
    log "Reloading Suricata..."
    if systemctl is-active --quiet suricata; then
        # Send SIGUSR2 for rule reload (non-disruptive)
        kill -USR2 "$(pidof suricata)" 2>/dev/null || systemctl reload suricata 2>/dev/null || systemctl restart suricata
        log "Suricata reloaded"
    else
        warn "Suricata is not running"
    fi
fi

# Summary
echo ""
echo "========================================"
echo "INSTALLATION COMPLETE"
echo "========================================"
echo ""
echo "Rules installed: $RULE_COUNT"
echo "Rules file: $SURICATA_RULES_DIR/ccdc-pii.rules"
echo ""
echo "Rules categories:"
echo "  - PII Detection (SSN, Credit Cards, Emails)"
echo "  - Credential Leakage (Passwords, API Keys)"
echo "  - File Exfiltration (passwd, shadow, SAM)"
echo "  - Reverse Shell Detection"
echo "  - Webshell Patterns"
echo "  - Cryptocurrency Mining"
echo "  - DNS Exfiltration"
echo ""
echo "To reload Suricata now:"
echo "  systemctl reload suricata"
echo ""
echo "To view alerts:"
echo "  tail -f /var/log/suricata/fast.log | grep CCDC"
echo "  tail -f /var/log/suricata/eve.json | jq '.alert'"
echo ""

exit 0
