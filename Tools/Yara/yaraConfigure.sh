#!/bin/bash

# CCDC Development - LMD Yara Rules Updater
# This script downloads the signature-base Yara rules, removes problematic files
# at the source, and combines the rest into a single master rule file for LMD.
# Run as root or with sudo.
 
set -e
set -o pipefail

# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
YARA_RULES_SRC_DIR="${CLONE_DIR}/yara"
# LMD's file for all custom user Yara rules
LMD_USER_RULES_FILE="/usr/local/maldetect/sigs/user.yara"
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

# Function to check for dependencies
check_deps() {
    local missing_deps=0
    # We don't need yarac, just git, find, xargs, and cat
    for cmd in git find xargs cat; do
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

# Function to remove problematic rules at the source
remove_problematic_rules() {
    log "Removing problematic rule files *before* combining..."

    # This list contains wildcards for files that cause syntax errors
    # or rely on external variables LMD does not support.
    local rules_to_delete=(
        # --- Problematic files from our debugging ---
        "*3cx*"             # Caused "SUSP APT 3CX" error
        "*screenconnect*"   # Caused "SUSP ScreenConnect" errors
        "*vcruntime*"       # Caused "SUSP VCRuntime" error
        "*base64_pe*"       # Caused "SUSP Double Base64" error
        "*poisonivy*"       # Caused "PoisonIvy Sample 6" error

        # --- Your original list ---
        "*apt_barracuda_esg_unc4841_jun23.yar*"
        "*apt_cobaltstrike.yar*"
        "*apt_tetris.yar*"
        "*configured_vulns_ext_vars.yar*"
        "*expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar*"
        "*expl_cleo_dec24.yar*"
        "*expl_commvault_cve_2025_57791.yar*"
        "*expl_outlook_cve_2023_23397.yar*"
        "*gen_fake_amsi_dll.yar*"
        "*gen_gcti_cobaltstrike.yar*"
        "*gen_susp_js_obfuscatorio.yar*"
        "*gen_susp_xor.yar*"
        "*gen_webshells_ext_vars.yar*"
        "*gen_xor_hunting.yar*"
        "*general_cloaking.yar*"
        "*generic_anomalies.yar*"
        "*mal_lockbit_lnx_macos_apr23.yar*"
        "*thor-hacktools.yar*"
        "*thor_inverse_matches.yar*"
        "*vuln_paloalto_cve_2024_3400_apr24.yar*"
        "*yara-rules_vuln_drivers_strict_renamed.yar*"
        "*yara_mixed_ext_vars.yar*"
    )

    local deleted_count=0
    for pattern in "${rules_to_delete[@]}"; do
        # Find files matching the pattern and delete them.
        # This is safer than rm as it handles "no match" gracefully.
        find "$YARA_RULES_SRC_DIR" -type f -name "$pattern" -print -delete | while read -r file; do
            log "  - Removed: $(basename "$file")"
            ((deleted_count++))
        done
    done

    log "Removed ${deleted_count} problematic rule files."
}

# Function to build the master rule file
build_master_rule_file() {
    log "Finding and concatenating all remaining .yar/.yara files..."
    
    # This is now a simple, clean combination step.
    # All problematic files have already been deleted.
    find "${YARA_RULES_SRC_DIR}" -type f \( -name "*.yar" -o -name "*.yara" \) | \
        xargs cat > "$LMD_USER_RULES_FILE"

    if [[ ! -s "$LMD_USER_RULES_FILE" ]]; then
        log "ERROR: The master rules file ('$LMD_USER_RULES_FILE') is empty."
        log "This usually means that the git clone failed or no rules were found."
        exit 1
    fi

    # Set standard permissions
    chmod 644 "$LMD_USER_RULES_FILE"

    log "Master rule file created successfully at ${LMD_USER_RULES_FILE}."
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
    
    # Install Yara, as LMD needs it to use the rules
    echo "--------------------------------------------------"
    echo "STEP 1: Installing Yara (needed by LMD)..."
    echo "--------------------------------------------------"
    if command -v apt-get &> /dev/null; then
        echo "Debian/Ubuntu based system detected. Using apt-get..."
        apt-get update -y > /dev/null 2>&1
        apt-get install yara -y
        
    elif command -v dnf &> /dev/null; then
        echo "RHEL/Fedora based system detected. Using dnf..."
        dnf install yara -y
        
    elif command -v yum &> /dev/null; then
        echo "RHEL/CentOS based system-detected. Using yum..."
        yum install yara -y
        
    else
        echo "Unsupported package manager. Please install Yara manually."
        exit 1
    fi
    echo "Yara installed successfully."
    
    check_root
    check_deps
    download_rules
    remove_problematic_rules
    build_master_rule_file
    cleanup

    log "--- LMD Yara Rules Update Complete ---"
}

main "$@"

