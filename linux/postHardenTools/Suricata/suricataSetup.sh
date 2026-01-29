#!/bin/bash

# ==============================================================================
# Suricata IPS Mode Installer and Configurator (v3.0)
#
# Description: This script automates the installation of Suricata on
#              Debian-based and Red Hat-based systems. It configures Suricata
#              for IPS mode, validates the configuration, and safely applies
#              persistent firewall rules.
#
# WARNING: This script will modify system packages and firewall settings.
#          It is intended for use on a dedicated security monitoring
#          system or a system you fully control. Run with caution.
#
# Usage: sudo ./suricataSetup.sh
# ==============================================================================

# --- Script Configuration ---
set -euo pipefail

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Functions ---

print_header() {
    echo "======================================================================"
    echo -e " ${GREEN}$1${NC}"
    echo "======================================================================"
}

exit_with_error() {
    echo " "
    echo -e "${RED}[ERROR] $1${NC}" >&2
    echo "Aborting script."
    exit 1
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# --- Pre-flight Checks ---

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
    exit_with_error "This script must be run as root. Please use sudo."
fi

# 2. Detect OS and set package manager
print_header "Step 1: Detecting System and Installing Prerequisites"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=${ID_LIKE:-""}
else
    exit_with_error "Cannot determine OS from /etc/os-release. Aborting."
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID" == "linuxmint" || " $OS_ID_LIKE " == *"debian"* ]]; then
    OS_FAMILY="debian"
    PKG_MANAGER="apt-get"
    echo "Detected Debian-based system ($OS_ID). Using APT."
    $PKG_MANAGER update > /dev/null
    $PKG_MANAGER install -y software-properties-common curl

elif [[ "$OS_ID" == "fedora" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID" == "centos" || "$OS_ID" == "ol" || "$OS_ID" == "rhel" || " $OS_ID_LIKE " == *"rhel"* || " $OS_ID_LIKE " == *"centos"* ]]; then
    OS_FAMILY="redhat"
    if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
    echo "Detected Red Hat-based system ($OS_ID). Using $PKG_MANAGER."
    $PKG_MANAGER install -y curl
else
    exit_with_error "Unsupported distribution: '$OS_ID'. This script supports Debian and Red Hat families."
fi

# --- User Input ---

print_header "Suricata IPS Configuration"
echo "This script will install and configure Suricata in IPS mode."
echo " "

# Get HOME_NET from user
echo -e "Add multiple network ranges as comma-separated, with the following syntax:"
echo -e "192.168.0.0/16,172.16.0.0/16,10.0.0.0/8"
read -r -p "Enter your home network range (e.g., 192.168.1.0/24): " HOME_NET
if [ -z "$HOME_NET" ]; then
    exit_with_error "Home network range cannot be empty."
fi

# Get network interface from user
echo " "
echo "Available network interfaces:"
ip -br a | awk '{print $1}' | grep -v "lo"
echo " "
read -r -p "Enter the network interface to monitor (e.g., eth0): " IFACE
if [ -z "$IFACE" ]; then
    exit_with_error "Network interface cannot be empty."
fi

# Fail-open vs fail-closed
echo " "
echo "Firewall mode for NFQUEUE:"
echo "  1) Fail-closed (more secure) - traffic is BLOCKED if Suricata goes down"
echo "  2) Fail-open (safer for availability) - traffic BYPASSES inspection if Suricata goes down"
read -r -p "Select mode [1/2] (default: 1): " FW_MODE
FW_MODE=${FW_MODE:-1}
if [[ "$FW_MODE" != "1" && "$FW_MODE" != "2" ]]; then
    print_warning "Invalid selection, defaulting to fail-closed."
    FW_MODE="1"
fi

# Alert-to-drop conversion
echo " "
echo "Rule action mode:"
echo "  1) Keep default actions (alert only - IDS behavior, logs but does not block)"
echo "  2) Convert all alert rules to drop (aggressive IPS - blocks matching traffic)"
read -r -p "Select mode [1/2] (default: 1): " RULE_MODE
RULE_MODE=${RULE_MODE:-1}

echo " "
echo "Configuration:"
echo "  - Home Network:  $HOME_NET"
echo "  - Interface:     $IFACE"
if [ "$FW_MODE" == "2" ]; then
    echo "  - Firewall Mode: Fail-open (--queue-bypass)"
else
    echo "  - Firewall Mode: Fail-closed"
fi
if [ "$RULE_MODE" == "2" ]; then
    echo "  - Rule Actions:  All alerts converted to DROP"
else
    echo "  - Rule Actions:  Default (alert only)"
fi
echo " "
read -r -p "Is this correct? (y/n): " confirm
if [[ "$confirm" != [yY] ]]; then
    echo "Script cancelled by user."
    exit 0
fi


# --- Installation ---

print_header "Step 2: Installing Suricata and Firewall Tools"
case "$OS_FAMILY" in
    "debian")
        # PPA is only available on Ubuntu; other Debian-family distros use default repos
        if [[ "$OS_ID" == "ubuntu" ]]; then
            add-apt-repository -y ppa:oisf/suricata-stable || print_warning "Failed to add Suricata PPA. Falling back to default repos."
        else
            print_warning "PPA not available for $OS_ID. Installing from default repositories."
        fi
        $PKG_MANAGER update
        $PKG_MANAGER install -y suricata iptables-persistent || exit_with_error "Failed to install Suricata and iptables-persistent."
        ;;
    "redhat")
        # Install correct COPR plugin based on package manager
        if [ "$PKG_MANAGER" == "dnf" ]; then
            $PKG_MANAGER install -y epel-release dnf-plugins-core
        else # yum
            $PKG_MANAGER install -y epel-release yum-plugin-copr
        fi
        $PKG_MANAGER copr enable -y @oisf/suricata-stable || exit_with_error "Failed to enable Suricata COPR repository."
        $PKG_MANAGER install -y suricata iptables-services || exit_with_error "Failed to install Suricata and iptables-services."
        ;;
esac
echo -e "${GREEN}Installation complete.${NC}"


# --- Rule Management ---

print_header "Step 3: Updating Suricata Rules and Enabling Sources"

# Enable additional rule sources
echo "Enabling additional rule sources..."
suricata-update enable-source ptresearch/attackdetection || print_warning "Could not enable ptresearch/attackdetection source."
suricata-update enable-source oisf/trafficid || print_warning "Could not enable oisf/trafficid source."
suricata-update enable-source sslbl/ja3-fingerprints || print_warning "Could not enable sslbl/ja3-fingerprints source."

# Update all rules
suricata-update || exit_with_error "Failed to update Suricata rules."

# Convert alert rules to drop if requested
if [ "$RULE_MODE" == "2" ]; then
    RULES_FILE="/var/lib/suricata/rules/suricata.rules"
    if [ -f "$RULES_FILE" ]; then
        ALERT_COUNT=$(grep -c '^alert' "$RULES_FILE" || true)
        print_warning "This will convert $ALERT_COUNT alert rules to drop. Overly broad rules may block legitimate traffic."
        echo "Converting all 'alert' rules to 'drop'..."
        sed -i 's/^alert/drop/' "$RULES_FILE"
        echo -e "${GREEN}$ALERT_COUNT rules converted to drop.${NC}"
    else
        print_warning "Rules file not found at $RULES_FILE. Skipping alert-to-drop conversion."
    fi
fi

echo -e "${GREEN}Rules updated successfully.${NC}"


# --- Configuration ---

print_header "Step 4: Configuring suricata.yaml and System Service"
SURICATA_CONF="/etc/suricata/suricata.yaml"

# Set OS-specific paths
if [ "$OS_FAMILY" == "debian" ]; then
    SURICATA_DEFAULTS="/etc/default/suricata"
else # redhat
    SURICATA_DEFAULTS="/etc/sysconfig/suricata"
fi

# Backup the original configuration file
cp "$SURICATA_CONF" "${SURICATA_CONF}.bak.$(date +%s)"
echo "Backed up original YAML configuration."

# Configure suricata.yaml
echo "Configuring suricata.yaml..."
sed -i 's/# ja4: off/ja4: on/g' "$SURICATA_CONF"
sed -i 's/#ja3-fingerprints\: auto/ja3-fingerprints\: auto/g' "$SURICATA_CONF"
sed -i 's/#ja4-fingerprints\: auto/ja4-fingerprints\: auto/g' "$SURICATA_CONF"
sed -i 's/#encryption-handling\: default/encryption-handling\: default/g' "$SURICATA_CONF"

# Set HOME_NET — escape brackets and slashes for sed
sed -i "s|HOME_NET:.*|HOME_NET: \"[$HOME_NET]\"|" "$SURICATA_CONF"

# Configure system service for NFQUEUE mode
echo "Configuring system service for NFQUEUE (IPS) mode..."
if [ -f "$SURICATA_DEFAULTS" ]; then
    sed -i 's/^LISTENMODE=.*/LISTENMODE=nfqueue/' "$SURICATA_DEFAULTS"
else
    echo 'LISTENMODE=nfqueue' > "$SURICATA_DEFAULTS"
fi

# Ensure log directory exists and has correct permissions
echo "Ensuring correct log directory permissions..."
mkdir -p /var/log/suricata
# Ensure suricata user and group exist before changing ownership
groupadd -r suricata &>/dev/null || true
useradd -r -g suricata -d /var/lib/suricata -s /sbin/nologin -c "Suricata IDS" suricata &>/dev/null || true
chown -R suricata:suricata /var/log/suricata

# Grant Wazuh agent access to Suricata logs
if id "wazuh" &>/dev/null; then
    echo "Adding wazuh user to suricata group for log access..."
    usermod -a -G suricata wazuh
else
    echo "Wazuh user not found. Skipping group modification."
    echo "If you install a Wazuh agent later, manually add the 'wazuh' user to the 'suricata' group."
fi

# Grant Splunk forwarder access to Suricata logs via ACL
if id "splunk" &>/dev/null; then
    echo "Granting splunk user read access to Suricata logs via ACL..."
    if command -v setfacl &>/dev/null; then
        setfacl -R -m u:splunk:rX /var/log/suricata
        setfacl -d -m u:splunk:rX /var/log/suricata
    else
        print_warning "setfacl not found. Install acl package to grant Splunk log access."
    fi
else
    echo "Splunk user not found. Skipping ACL setup."
fi

echo -e "${GREEN}Configuration updated.${NC}"


# --- Validation ---

print_header "Step 5: Validating Suricata Configuration"
echo "Running a pre-flight test on the configuration and rules..."
if ! /usr/bin/suricata -T -c "$SURICATA_CONF" -v; then
    exit_with_error "Suricata configuration test failed. Please review the errors above."
fi
echo -e "${GREEN}Configuration and rules validated successfully.${NC}"


# --- Firewall Setup & Service Start ---

print_header "Step 6: Applying Firewall Rules and Starting Suricata"

# Function to clean up ONLY Suricata NFQUEUE rules on failure (preserves existing firewall rules)
cleanup_on_failure() {
    echo " "
    echo -e "${RED}An error occurred. Rolling back Suricata NFQUEUE rules only...${NC}"
    iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null || true
    iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    echo "Suricata NFQUEUE rules removed. Existing firewall rules preserved."
}

# Trap errors to call the cleanup function
trap cleanup_on_failure ERR

# --- Firewall Configuration ---
case "$OS_FAMILY" in
    "debian")
        echo "Configuring iptables-persistent..."
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        systemctl enable netfilter-persistent
        ;;
    "redhat")
        if systemctl is-active --quiet firewalld; then
            echo "Disabling firewalld to use iptables..."
            systemctl stop firewalld
            systemctl disable firewalld
        fi
        echo "Enabling iptables-services..."
        systemctl enable iptables
        ;;
esac

# Remove any existing Suricata NFQUEUE rules before adding new ones (idempotent)
echo "Cleaning any previous Suricata NFQUEUE rules..."
iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null || true
iptables -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true

# Append NFQUEUE rules to existing firewall (preserves all hardening rules)
if [ "$FW_MODE" == "2" ]; then
    echo "Appending NFQUEUE rules with --queue-bypass (fail-open)..."
    iptables -A INPUT -j NFQUEUE --queue-num 0 --queue-bypass
    iptables -A OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
    iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
else
    echo "Appending NFQUEUE rules without bypass (fail-closed)..."
    iptables -A INPUT -j NFQUEUE --queue-num 0
    iptables -A OUTPUT -j NFQUEUE --queue-num 0
    iptables -A FORWARD -j NFQUEUE --queue-num 0
fi

# --- Save Firewall Rules ---
echo "Saving iptables rules..."
case "$OS_FAMILY" in
    "debian")
        iptables-save > /etc/iptables/rules.v4
        ;;
    "redhat")
        iptables-save > /etc/sysconfig/iptables
        ;;
esac
echo "NFQUEUE rules appended and all rules made persistent."

# --- Service Start ---
# Stop any running instance and clean up the old PID file
systemctl stop suricata &>/dev/null || true
rm -f /var/run/suricata.pid

# Reload systemd to pick up changes
systemctl daemon-reload
echo "Starting Suricata service..."
systemctl start suricata

# Verify that the service has started
echo "Waiting for Suricata engine to initialize..."
SURICATA_LOG="/var/log/suricata/suricata.log"

for i in $(seq 1 30); do
    if systemctl is-active --quiet suricata; then
        if [ -f "$SURICATA_LOG" ] && grep -q "engine started" "$SURICATA_LOG" 2>/dev/null; then
            echo -e "${GREEN}Suricata service is active and engine has started.${NC}"
            trap - ERR
            break
        fi
    fi

    if [ "$i" -eq 30 ]; then
        if ! systemctl is-active --quiet suricata; then
            exit_with_error "Suricata service is not active. Check 'systemctl status suricata' and 'journalctl -u suricata'."
        else
            print_warning "Suricata service is active but engine startup message not yet found in logs. Proceeding anyway."
            trap - ERR
        fi
    fi
    sleep 1
done


# --- Test ---

print_header "Step 7: Running Live Test"

# Perform the test
echo "Running test with curl http://testmynids.org/uid/index.html..."
echo "A successful IPS block will cause this command to hang or fail."
curl --max-time 10 http://testmynids.org/uid/index.html || true

# Check the logs for the specific alert
LOG_FILE="/var/log/suricata/fast.log"
echo "Checking logs for test signature..."
sleep 2

if [ -f "$LOG_FILE" ] && grep -q "testmynids.org" "$LOG_FILE"; then
    echo " "
    echo -e "${GREEN}SUCCESS: Test signature found in logs!${NC}"
    echo "Suricata is successfully monitoring traffic in IPS mode."
    grep "testmynids.org" "$LOG_FILE"
else
    echo " "
    echo -e "${RED}FAILED: Test signature was NOT found in logs.${NC}"
    echo "Please check your configuration and network traffic."
    echo "Log file checked: $LOG_FILE"
fi

print_header "Setup Complete"
echo "To see live alerts, run: tail -f /var/log/suricata/eve.json"
echo "To stop Suricata, run: systemctl stop suricata && iptables -F"
