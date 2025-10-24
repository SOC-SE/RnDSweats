#!/bin/bash

# CCDC Development - Community Yara Rules Builder & Installer
# This script installs Yara and jq, downloads the signature-base Yara rules,
# removes problematic files at the source using find -delete, and combines
# the rest into a single master rule file saved in the current directory.
# Run as root or with sudo.

# Removing set -e and -o pipefail to ensure the script runs completely
# set -e
# set -o pipefail

# --- Variables ---
REPO_URL="https://github.com/neo23x0/signature-base.git"
CLONE_DIR="/tmp/signature-base"
YARA_RULES_SRC_DIR="${CLONE_DIR}/yara"
# Output file in the current directory
MASTER_RULES_FILE="./master_community_rules.yar"
LOG_FILE="/var/log/community_yara_builder.log"

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
    # Dependencies needed: git, find, xargs, cat, yara, jq
    for cmd in git find xargs cat yara jq; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR: Dependency '$cmd' not found."
            missing_deps=1
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log "Please install the missing dependencies (git, findutils, coreutils, yara, jq) and run the script again."
        exit 1
    fi
    log "All dependencies are satisfied."
}

# Function to install dependencies (Yara & jq)
install_deps() {
    log "Installing dependencies (Yara & jq)..."
    if command -v apt-get &> /dev/null; then
        echo "Debian/Ubuntu based system detected. Using apt-get..."
        apt-get update -y > /dev/null 2>&1
        apt-get install yara jq -y
        
    elif command -v dnf &> /dev/null; then
        echo "RHEL/Fedora based system detected. Using dnf..."
        dnf install yara jq -y
        
    elif command -v yum &> /dev/null; then
        echo "RHEL/CentOS based system detected. Using yum..."
        # JQ might be in EPEL repository for older CentOS
        if ! rpm -q epel-release > /dev/null 2>&1; then
            log "  - Installing EPEL repository for JQ..."
            yum install epel-release -y
        fi
        yum install yara jq -y
        
    else
        log "Unsupported package manager. Please install Yara and JQ manually."
        exit 1
    fi
    log "Dependencies installed successfully."
}

# Function to download the Yara rules
download_rules() {
    log "Downloading Yara rules from ${REPO_URL}..."
    rm -rf "$CLONE_DIR"
    git clone "$REPO_URL" "$CLONE_DIR"
    log "Rules downloaded successfully to ${CLONE_DIR}."
}

# Function to remove problematic rules at the source (Using find -delete)
remove_problematic_rules() {
    log "Removing problematic rule files *before* combining..."

    local rules_to_delete=(
        # --- Problematic files from our debugging ---
        "*3cx*"             # Caused "SUSP APT 3CX" error
        "*screenconnect*"   # Caused "SUSP ScreenConnect" errors
        "*vcruntime*"       # Caused "SUSP VCRuntime" error
        "*base64_pe*"       # Caused "SUSP Double Base64" error
        "*poisonivy*"       # Caused "PoisonIvy Sample 6" error
        "*Linux_Sudops*"    # Found later, causes issues
        "*gen_susp_obfuscation.yar*" # Contains SUSP_Reversed_Base64_Encoded_EXE

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

    local total_deleted_count=0
    for pattern in "${rules_to_delete[@]}"; do
        log "  - Searching for pattern: $pattern"
        
        # Use find -delete -print to remove and log files.
        # || true prevents the script from exiting if no files match.
        local deleted_files
        deleted_files=$(find "$YARA_RULES_SRC_DIR" -type f -name "$pattern" -delete -print 2>/dev/null || true)
        
        if [ -n "$deleted_files" ]; then
            while IFS= read -r file; do
                log "    - Removed: $(basename "$file")"
                ((total_deleted_count++))
            done <<< "$deleted_files"
        fi
    done

    log "Removed a total of ${total_deleted_count} problematic rule files."
}


# Function to build the master rule file
build_master_rule_file() {
    log "Finding and concatenating all remaining .yar/.yara files..."
    
    # Clear the old file before appending
    rm -f "$MASTER_RULES_FILE"
    touch "$MASTER_RULES_FILE"

    # Find all remaining rule files and append them
    find "${YARA_RULES_SRC_DIR}" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 | while IFS= read -r -d $'\0' file; do
        cat "$file" >> "$MASTER_RULES_FILE"
        # Add a newline between files for safety
        echo -e "\n" >> "$MASTER_RULES_FILE"
    done

    if [[ ! -s "$MASTER_RULES_FILE" ]]; then
        log "ERROR: The master rules file ('$MASTER_RULES_FILE') is empty."
        log "This usually means that the git clone failed or no rules were found after filtering."
        exit 1
    fi

    # Set standard permissions
    chmod 644 "$MASTER_RULES_FILE"

    log "Master rule file created successfully at ${MASTER_RULES_FILE}."
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
    echo "--- Community Yara Rules Builder Log ---" > "$LOG_FILE"
    
    check_root
    install_deps # Added back
    check_deps   # Added yara and jq check
    download_rules
    remove_problematic_rules
    build_master_rule_file
    cleanup

    log "--- Community Yara Rules Build Complete ---"
}

main "$@"

