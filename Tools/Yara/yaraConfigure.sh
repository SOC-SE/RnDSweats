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
    log "Creating a master index file with include statements..."

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
        -print | sed 's/^/include "/; s/$/"/' > "$MASTER_RULES_FILE_TMP"


    if [[ ! -s "$MASTER_RULES_FILE_TMP" ]]; then
        log "ERROR: The master rules file ('$MASTER_RULES_FILE_TMP') is empty."
        log "This usually means that the git clone failed or that the repository structure has changed."
        log "Please check the clone directory ('$CLONE_DIR') to investigate."
        exit 1
    fi

    log "Master index file created successfully at ${MASTER_RULES_FILE_TMP}."
}

# Function to compile the rules
compile_rules() {
    log "Compiling the final ruleset..."
    # The -w flag disables common warnings.
    # The -d flag defines external variables that many rules in this repo expect.
    # This allows us to compile rules that would otherwise fail, without having to exclude them.
    yarac -w \
    -d filename="dummy" \
    -d filepath="dummy" \
    -d extension="dummy" \
    -d filetype="dummy" \
    -d filesize=0 \
    "$MASTER_RULES_FILE_TMP" "${CLONE_DIR}/${COMPILED_RULES_FILE}"
    
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