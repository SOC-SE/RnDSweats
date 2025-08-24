#!/bin/sh

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}
USER="root"
GROUP="wazuh"

YARA_VERSION="${1:-4.5.4}"
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
YARA_SH_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/main/scripts/yara.sh"

OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
YARA_SH_PATH="/var/ossec/active-response/bin/yara.sh"
YARA_RULES_DEST_DIR="/var/ossec/ruleset/yara/rules"

# --- OS and Distribution Detection ---
DISTRO_FAMILY=""
PKG_MANAGER=""
INSTALL_CMD=""
UNINSTALL_CMD=""
DEV_PACKAGES=""
NOTIFY_SEND_PKG=""
ZENITY_PKG=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_FAMILY=${ID_LIKE:-$ID}
else
    error_message "Cannot determine Linux distribution from /etc/os-release."
    exit 1
fi

if echo "$OS_FAMILY" | grep -q -e "debian" -e "ubuntu"; then
    DISTRO_FAMILY="debian"
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
    UNINSTALL_CMD="apt remove -y"
    DEV_PACKAGES="automake libtool make gcc pkg-config flex bison curl libjansson-dev libmagic-dev libssl-dev"
    NOTIFY_SEND_PKG="libnotify-bin"
    ZENITY_PKG="zenity"
elif echo "$OS_FAMILY" | grep -q -e "rhel" -e "fedora" -e "centos"; then
    DISTRO_FAMILY="rhel"
    if command_exists dnf; then
        PKG_MANAGER="dnf"
    elif command_exists yum; then
        PKG_MANAGER="yum"
    else
        error_message "Neither DNF nor YUM is available on this system."
        exit 1
    fi
    INSTALL_CMD="$PKG_MANAGER install -y"
    UNINSTALL_CMD="$PKG_MANAGER remove -y"
    DEV_PACKAGES="automake libtool make gcc pkgconf-pkg-config flex bison curl jansson-devel file-devel openssl-devel"
    NOTIFY_SEND_PKG="libnotify"
    ZENITY_PKG="zenity"
else
    error_message "Unsupported Linux distribution family: $OS_FAMILY"
    exit 1
fi
# --- End Detection ---

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"
}

warn_message() {
    log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"
}

error_message() {
    log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"
}

success_message() {
    log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"
}

print_step() {
    log "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        # FIXED: Changed 'command_v' to 'command -v'
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# Create a temporary directory and ensure it's cleaned up on exit
TMP_DIR=$(mktemp -d)
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# FIXED: Set tarball and extraction directories inside the safe temporary directory
TAR_DIR="$TMP_DIR/yara-${YARA_VERSION}.tar.gz"
EXTRACT_DIR="$TMP_DIR/yara-${YARA_VERSION}"

# Ensure that the root:wazuh user and group exist, creating them if necessary
ensure_user_group() {
    info_message "Ensuring that the $USER:$GROUP user and group exist..."

    if ! id -u "$USER" >/dev/null 2>&1; then
        info_message "Creating user $USER..."
        if command -v useradd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then # For Alpine
            maybe_sudo adduser -D "$USER"
        else
            error_message "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        info_message "Creating group $GROUP..."
        if command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then # For Alpine
            maybe_sudo addgroup "$GROUP"
        else
            error_message "Unsupported OS for creating group."
            exit 1
        fi
    fi
}

# Function to change ownership of a file or directory
change_owner() {
    local path="$1"
    ensure_user_group
    maybe_sudo chown -R "$USER:$GROUP" "$path"
}

restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        info_message "Wazuh agent restarted successfully."
    else
        error_message "Error occurred during Wazuh agent restart."
    fi
}

download_yara_script() {
    maybe_sudo mkdir -p "$(dirname "$YARA_SH_PATH")"

    maybe_sudo curl -SL --progress-bar "$YARA_SH_URL" -o "$TMP_DIR/yara.sh" || {
        error_message "Failed to download yara.sh script."
    }

    maybe_sudo mv "$TMP_DIR/yara.sh" "$YARA_SH_PATH"
    (change_owner "$YARA_SH_PATH" && maybe_sudo chmod 750 "$YARA_SH_PATH") || {
        error_message "Error occurred during yara.sh file permissions change."
    }
    info_message "yara.sh script downloaded and installed successfully."
}

# LOGICAL FIX: This new function ADDS the required config instead of removing it.
update_ossec_conf() {
    info_message "Removing any previous YARA syscheck configurations..."
    # Remove old config to ensure a clean slate
    maybe_sudo sed -i '/<directories realtime="yes">\/home, \/root, \/bin, \/sbin<\/directories>/d' "$OSSEC_CONF_PATH"

    YARA_CONFIG='  <directories realtime="yes">/home, /root, /bin, /sbin</directories>'
    info_message "Adding YARA syscheck configuration to ossec.conf..."

    # Check if the config already exists before adding
    if ! grep -qF "$YARA_CONFIG" "$OSSEC_CONF_PATH"; then
        # Insert the configuration just before the closing </syscheck> tag for safety
        maybe_sudo sed -i '/<\/syscheck>/i \'"$YARA_CONFIG"'' "$OSSEC_CONF_PATH" || {
            error_message "Failed to add YARA directories to ossec.conf."
            exit 1
        }
        success_message "Successfully added YARA configuration to syscheck."
    else
        info_message "YARA syscheck configuration already exists."
    fi
}

remove_packaged_yara() {
    info_message "Checking for and removing existing package-manager versions of YARA..."
    case "$DISTRO_FAMILY" in
    debian)
        if command_exists dpkg && dpkg -s yara >/dev/null 2>&1; then
            info_message "Removing apt-installed YARA..."
            maybe_sudo apt-get remove -y yara
            maybe_sudo apt-get autoremove -y
        fi
        ;;
    rhel)
        if command_exists rpm && rpm -q yara >/dev/null 2>&1; then
            info_message "Removing yum/dnf-installed YARA..."
            maybe_sudo "$UNINSTALL_CMD" yara
        fi
        ;;
    esac
}

# FIX: Replaced fragile .deb download with a robust package manager call.
ensure_desktop_tools() {
    info_message "Ensuring desktop notification tools are installed..."
    if ! command_exists notify-send || ! command_exists zenity; then
        info_message "Installing notification tools: $NOTIFY_SEND_PKG and $ZENITY_PKG"
        if [ "$DISTRO_FAMILY" = "debian" ]; then
            maybe_sudo apt-get update -qq
        fi
        maybe_sudo "$INSTALL_CMD" "$NOTIFY_SEND_PKG" "$ZENITY_PKG" || {
            error_message "Failed to install desktop notification tools."
            exit 1
        }
    else
        info_message "Desktop notification tools are already installed."
    fi
}

install_yara_from_source() {
    info_message "Installing YARA v${YARA_VERSION} from source on Linux ($DISTRO_FAMILY)"

    print_step "1" "Installing build dependencies"
    if [ "$DISTRO_FAMILY" = "debian" ]; then
        maybe_sudo apt update -qq
    fi
    maybe_sudo $INSTALL_CMD $DEV_PACKAGES

    print_step "2" "Downloading YARA $YARA_VERSION to $TMP_DIR"
    if ! curl -fsSL -o "$TAR_DIR" "$YARA_URL"; then
        error_message "Failed to download YARA source tarball"
        return 1
    fi

    print_step "3" "Extracting source to $TMP_DIR"
    mkdir -p "$EXTRACT_DIR"
    if ! tar -xzf "$TAR_DIR" -C "$TMP_DIR" --strip-components=1; then
        error_message "Failed to extract YARA tarball"
        return 1
    fi

    print_step "4" "Building & installing"
    cd "$EXTRACT_DIR"

    info_message "Running bootstrap.sh"
    maybe_sudo ./bootstrap.sh

    info_message "Configuring build"
    maybe_sudo ./configure --disable-silent-rules --enable-cuckoo --enable-magic --enable-dotnet --enable-macho --enable-dex --with-crypto

    info_message "Compiling"
    maybe_sudo make

    info_message "Installing"
    maybe_sudo make install

    info_message "Running test suite"
    maybe_sudo make check

    info_message "Updating shared library cache..."
    maybe_sudo ldconfig

    cd - >/dev/null

    success_message "YARA v${YARA_VERSION} installed from source successfully"
}

install_yara_and_tools() {
    remove_packaged_yara
    ensure_desktop_tools

    if command_exists yara && [ "$(yara --version)" = "$YARA_VERSION" ]; then
        info_message "YARA version $YARA_VERSION is already installed. Skipping installation."
    else
        info_message "Installing YARA..."
        install_yara_from_source
    fi
}

download_yara_rules() {
    local YARA_RULES_FILE="$TMP_DIR/yara_rules.yar"
    local YARA_RULES_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-yara/refs/heads/main/rules/yara_rules.yar"
    maybe_sudo curl -SL --progress-bar "$YARA_RULES_URL" -o "$YARA_RULES_FILE"

    if [ -s "$YARA_RULES_FILE" ]; then
        maybe_sudo mkdir -p "$YARA_RULES_DEST_DIR"
        maybe_sudo mv "$YARA_RULES_FILE" "$YARA_RULES_DEST_DIR/yara_rules.yar"
        change_owner "$YARA_RULES_DEST_DIR"
        info_message "YARA rules moved to $YARA_RULES_DEST_DIR."
    else
        error_message "Error occurred during YARA rules download."
        exit 1
    fi
}

validate_installation() {

    local VALIDATION_STATUS="TRUE"

    if ! command_exists notify-send; then
        warn_message "notify-send is not installed."
        VALIDATION_STATUS="FALSE"
    fi

    if command_exists yara; then
        if [ "$(yara --version)" = "$YARA_VERSION" ]; then
            success_message "Yara version $YARA_VERSION is installed."
        else
            warn_message "Yara version mismatch. Expected $YARA_VERSION, but found $(yara --version)."
            VALIDATION_STATUS="FALSE"
        fi
    else
        error_message "Yara command is not available. Please check the installation."
        VALIDATION_STATUS="FALSE"
    fi

    if [ ! -f "$YARA_RULES_DEST_DIR/yara_rules.yar" ]; then
        warn_message "Yara rules file not present at $YARA_RULES_DEST_DIR/yara_rules.yar."
        VALIDATION_STATUS="FALSE"
    else
        success_message "Yara rules file exists at $YARA_RULES_DEST_DIR/yara_rules.yar."
    fi

    if [ ! -f "$YARA_SH_PATH" ]; then
        warn_message "Yara active response script not present at $YARA_SH_PATH."
        VALIDATION_STATUS="FALSE"
    else
        success_message "Yara active response script exists at $YARA_SH_PATH."
    fi

    if [ "$VALIDATION_STATUS" = "TRUE" ]; then
        success_message "YARA installation and configuration validation completed successfully."
    else
        error_message "YARA installation and configuration validation failed. Please check the warnings above."
        exit 1
    fi
}

#--------------------------------------------#

# Step 1: Install YARA and necessary tools
print_step 1 "Installing YARA and necessary tools..."
install_yara_and_tools

# Step 2: Download YARA rules
print_step 2 "Downloading YARA rules..."
download_yara_rules

# Step 3: Download yara.sh script
print_step 3 "Downloading yara.sh script..."
download_yara_script

# Step 4: Update Wazuh agent configuration file
print_step 4 "Updating Wazuh agent configuration file..."
if [ -f "$OSSEC_CONF_PATH" ]; then
    update_ossec_conf
else
    warn_message "OSSEC configuration file not found at $OSSEC_CONF_PATH."
fi

# Step 5: Restart Wazuh agent
print_step 5 "Restarting Wazuh agent..."
restart_wazuh_agent

# Step 6: Cleanup (handled by trap)
print_step 6 "Cleaning up temporary files..."
info_message "Temporary files will be cleaned up automatically upon exit."

# Step 7: Validate installation and configuration
print_step 7 "Validating installation and configuration..."
validate_installation
