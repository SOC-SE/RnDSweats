#!/bin/bash

# CCDC Development - LMD Yara Rules Updater
# This script downloads the signature-base Yara rules, removes problematic ones,
# and combines them into a single master rule file for use with LMD.
# Run as root or with sudo.
 
set -e
set -o pipefail

# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
# LMD's file for all custom user Yara rules
LMD_USER_RULES_FILE="/usr/local/maldetect/sigs/compiled.yara"
LOG_FILE="/var/log/lmd_yara_updater.log"
MASTER_RULES_FILE_TMP="${CLONE_DIR}/master_plain.yar"


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
    # We just need common shell tools and git
    for cmd in git find awk grep sed xargs tee; do
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

# Function to download the Yara rules
download_rules() {
    log "Downloading Yara rules from ${REPO_URL}..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
    log "Rules downloaded successfully to ${CLONE_DIR}."
}

# Function to assemble and filter the rules
build_master_rule_file() {
    log "Finding and concatenating all .yar files..."

    # Define directories to scan for rules.
    declare -a directories_to_include=(
        "${CLONE_DIR}/yara/"
    )

    # This is a comprehensive exclusion list combining the maintainer's recommendations
    # and files found to have persistent syntax errors.

    # This fix sucks. I hate to exclude so many of these, only a chunk of them are recommended to be remove by the creator of the yara rules
    # repo. Hopefully I can fix this in the future, but I'm too fucking tired right now. FML, this feels disgusting, but some coverage is
    # better than no coverage. - Sam 2025
    find "${directories_to_include[@]}" -type f \( -name "*.yar" -o -name "*.yara" \) \
        -not -path "*/apt_barracuda_esg_unc4841_jun23.yar" \
        -not -path "*/apt_cobaltstrike.yar" \
        -not -path "*/apt_tetris.yar" \
        -not -path "*/configured_vulns_ext_vars.yar" \
        -not -path "*/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar" \
        -not -path "*/expl_cleo_dec24.yar" \
        -not -path "*/expl_commvault_cve_2025_57791.yar" \
        -not -path "*/expl_outlook_cve_2023_23397.yar" \
        -not -path "*/gen_fake_amsi_dll.yar" \
        -not -path "*/gen_gcti_cobaltstrike.yar" \
        -not -path "*/gen_susp_js_obfuscatorio.yar" \
        -not -path "*/gen_susp_xor.yar" \
        -not -path "*/gen_webshells_ext_vars.yar" \
        -not -path "*/gen_xor_hunting.yar" \
        -not -path "*/general_cloaking.yar" \
        -not -path "*/generic_anomalies.yar" \
        -not -path "*/mal_lockbit_lnx_macos_apr23.yar" \
        -not -path "*/thor-hacktools.yar" \
        -not -path "*/thor_inverse_matches.yar" \
        -not -path "*/vuln_paloalto_cve_2024_3400_apr24.yar" \
        -not -path "*/yara-rules_vuln_drivers_strict_renamed.yar" \
        -not -path "*/yara_mixed_ext_vars.yar" \
        -print0 | xargs -0 cat > "$MASTER_RULES_FILE_TMP"


    if [[ ! -s "$MASTER_RULES_FILE_TMP" ]]; then
        log "ERROR: The master rules file ('$MASTER_RULES_FILE_TMP') is empty."
        log "This usually means that the git clone failed or that the repository structure has changed."
        log "Please check the clone directory ('$CLONE_DIR') to investigate."
        exit 1
    fi

    log "Master rule file (plain text) created successfully at ${MASTER_RULES_FILE_TMP}."
}

# Function to deploy the compiled rules
deploy_master_rule_file() {
    log "Deploying master rule file to ${LMD_USER_RULES_FILE}..."
    mkdir -p "$(dirname "$LMD_USER_RULES_FILE")"
    
    # Move the new file into place, overwriting the old one.
    # This prevents rules from being duplicated on subsequent runs.
    mv "$MASTER_RULES_FILE_TMP" "$LMD_USER_RULES_FILE"
    
    # Set standard permissions
    chmod 644 "$LMD_USER_RULES_FILE"
    
    log "Deployment complete. LMD will use these rules on its next scan."
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

    # Install Dependencies (Yara)
    echo "--------------------------------------------------"
    echo "STEP 1: Installing Yara..."
    echo "--------------------------------------------------"
    if command -v apt-get &> /dev/null; then
        echo "Debian/Ubuntu based system detected. Using apt-get..."
        apt-get update -y > /dev/null 2>&1
        apt-get install yara -y
        
    elif command -v dnf &> /dev/null; then
        echo "RHEL/Fedora based system detected. Using dnf..."
        dnf install yara -y
        
    elif command -v yum &> /dev/null; then
        echo "RHEL/CentOS based system detected. Using yum..."
        yum install yara -y
        
    else
        echo "Unsupported package manager. Please install Yara manually."
        exit 1
    fi
    echo "Yara installed successfully."

    
    check_root
    check_deps
    download_rules
    build_master_rule_file
    deploy_master_rule_file
    cleanup

    log "--- LMD Yara Rules Update Complete ---"
}

main "$@"
