#!/bin/bash

# ==============================================================================
# Suricata IPS Mode Installer and Configurator (v2.6 - Optimized)
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
# Usage: ./suricata_ips_setup.sh
# ==============================================================================

# --- Script Configuration ---
set -e

# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "======================================================================"
    echo " $1"
    echo "======================================================================"
}

# Function to print an error message and exit
exit_with_error() {
    echo " "
    echo "[ERROR] $1" >&2
    echo "Aborting script."
    exit 1
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
    if command -v dnf &> /dev/null;
    then
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
echo "We need two pieces of information to get started."
echo " "

# Get HOME_NET from user
read -p "Enter your home network range (e.g., 192.168.1.0/24): " HOME_NET
if [ -z "$HOME_NET" ]; then
    exit_with_error "Home network range cannot be empty."
fi

# Get network interface from user
echo " "
echo "Available network interfaces:"
ip -br a | awk '{print $1}' | grep -v "lo"
echo " "
read -p "Enter the network interface to monitor (e.g., eth0): " IFACE
if [ -z "$IFACE" ]; then
    exit_with_error "Network interface cannot be empty."
fi

echo " "
echo "Configuration:"
echo "  - Home Network: $HOME_NET"
echo "  - Interface:    $IFACE"
echo " "
read -p "Is this correct? (y/n): " confirm
if [[ "$confirm" != [yY] ]]; then
    echo "Script cancelled by user."
    exit 0
fi


# --- Installation ---

print_header "Step 2: Installing Suricata and Firewall Tools"
case "$OS_FAMILY" in
    "debian")
        add-apt-repository -y ppa:oisf/suricata-stable || exit_with_error "Failed to add Suricata PPA."
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
echo "Installation complete."


# --- Rule Management ---

print_header "Step 3: Updating Suricata Rules"
suricata-update || exit_with_error "Failed to update Suricata rules."
echo "Rules updated successfully."


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
echo "Backed up original YAML configuration to ${SURICATA_CONF}.bak.<timestamp>"

# Atomically configure suricata.yaml using a single sed command
echo "Configuring suricata.yaml..."
sed -i -E \
    -e "s|^(\s*HOME_NET:\s*)\\"\\[.*\\\\]\\"|\1\"\\[$HOME_NET\"\"|g" \
    -e "s/^    - interface: .*/    - interface: default/" \
    -e 's/^(\s*- eve-log:\s*)enabled: no/\1enabled: yes/' \
    -e '/- eve-log:/,/types:/s/^(\s*)#(\s*-\s*(alert|http|dns|tls|files|ssh|flow))/\1\2/' \
    -e 's/^(\s*)#\s*(ja3-fingerprints:).*/\1\2 yes/' \
    -e 's/^(\s*)#\s*(ja4-fingerprints:).*/\1\2 yes/' \
    -e 's/^(\s*ja4:).*/\1 on/' \
    "$SURICATA_CONF"

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

echo "Configuration updated."


# --- Validation ---

print_header "Step 5: Validating Suricata Configuration"
echo "Running a pre-flight test on the configuration and rules..."
if ! /usr/bin/suricata -T -c "$SURICATA_CONF" -v; then
    exit_with_error "Suricata configuration test failed. Please review the errors above."
fi
echo "Configuration and rules validated successfully."


# --- Firewall Setup & Service Start ---

print_header "Step 6: Applying Firewall Rules and Starting Suricata"

# Function to clean up iptables rules on failure
cleanup_on_failure() {
    echo " "
    echo "‼️ An error occurred. Rolling back firewall rules to restore connectivity..."
    iptables -F
    echo "iptables rules flushed. Network should be restored."
}

# Trap errors to call the cleanup function
trap cleanup_on_failure ERR

# --- Firewall Configuration ---
case "$OS_FAMILY" in
    "debian")
        echo "Configuring iptables-persistent..."
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        # This is just to ensure the service is enabled, install was done earlier
        systemctl enable netfilter-persistent
        ;; 
    "redhat")
        if systemctl is-active --quiet firewalld;
        then
            echo "Disabling firewalld to use iptables..."
            systemctl stop firewalld
            systemctl disable firewalld
        fi
        echo "Enabling iptables-services..."
        systemctl enable iptables
        ;; 
esac

# Flush any existing rules to be safe
iptables -F

# Add bypass rules for stability
iptables -I INPUT 1 -i lo -j ACCEPT
iptables -I OUTPUT 1 -o lo -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Send NEW connections to NFQUEUE for Suricata
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
iptables -A FORWARD -j NFQUEUE --queue-num 0

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
echo "iptables rules added and made persistent."

# --- Service Start ---
# Stop any running instance and clean up the old PID file
systemctl stop suricata &>/dev/null || true
rm -f /var/run/suricata.pid # Remove stale PID file

# Reload systemd to pick up changes
systemctl daemon-reload
echo "Starting Suricata service..."
systemctl start suricata

# Verify that the service has started
echo "Waiting for Suricata engine to initialize..."
SURICATA_LOG="/var/log/suricata/suricata.log"

# Wait up to 30 seconds for the engine to start
for i in {1..30}; do
    if systemctl is-active --quiet suricata && grep -q "NFQ running in IPS mode" "$SURICATA_LOG"; then
        echo "✅ Suricata service is active and running in IPS mode."
        trap - ERR # Disable the error trap if we succeed
        break
    fi

    if [ "$i" -eq 30 ]; then
        echo "Timed out waiting for Suricata to start."
        if ! systemctl is-active --quiet suricata;
        then
            exit_with_error "Suricata service is not active. Check 'systemctl status suricata' and 'journalctl -u suricata'."
        else
            exit_with_error "Suricata service is active, but failed to initialize IPS mode. Check logs at $SURICATA_LOG"
        fi
    fi
    sleep 1
done

# --- Test ---

print_header "Step 7: Running Live Test"

# Perform the test
echo "Running test with curl http://testmynids.org/uid/index.html..."
echo "A successful IPS block will cause this command to hang or fail."
curl --max-time 10 http://testmynids.org/uid/index.html || true # Don't exit on failure

# Check the logs for the specific alert
LOG_FILE="/var/log/suricata/fast.log"
echo "Checking logs for test signature..."
sleep 2

if grep -q "testmynids.org" "$LOG_FILE"; then
    echo " "
    echo "✅ SUCCESS: Test signature found in logs!"
    echo "Suricata is successfully monitoring traffic in IPS mode."
    grep "testmynids.org" "$LOG_FILE"
else
    echo " "
    echo "❌ FAILED: Test signature was NOT found in logs."
    echo "Please check your configuration and network traffic."
    echo "Log file checked: $LOG_FILE"
fi

print_header "Setup Complete"
echo "To see live alerts, run: tail -f /var/log/suricata/eve.json"
echo "To stop Suricata, run: systemctl stop suricata && iptables -F"
