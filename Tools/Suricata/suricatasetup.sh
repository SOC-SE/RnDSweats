#!/bin/bash

# ==============================================================================
# Suricata IPS Mode Installer and Configurator (v2.4 - Systemd Integrated)
#
# Description: This script automates the installation of Suricata,
#              configures it for Intrusion Prevention System (IPS) mode using
#              the system's native service manager (systemd), validates the
#              configuration, and safely applies firewall rules.
#              Includes automatic rollback of firewall rules on failure.
#
# WARNING: This script will modify system packages and firewall settings.
#          It is intended for use on a dedicated security monitoring
#          system or a system you fully control. Run with caution.
#
# Usage: ./suricata_ips_setup.sh
# ==============================================================================

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

# 2. Check for a supported OS (Debian/Ubuntu)
if ! command -v apt-get &>/dev/null; then
    exit_with_error "This script is designed for Debian-based systems (like Ubuntu) that use APT."
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

print_header "Step 1: Installing Suricata and Dependencies"
apt-get install -y software-properties-common curl || exit_with_error "Failed to install software-properties-common."
add-apt-repository -y ppa:oisf/suricata-stable || exit_with_error "Failed to add Suricata PPA."
apt-get update
apt-get install -y suricata || exit_with_error "Failed to install Suricata."
echo "Installation complete."


# --- Rule Management ---

print_header "Step 2: Updating Suricata Rules"
suricata-update || exit_with_error "Failed to update Suricata rules."
echo "Rules updated successfully."


# --- Configuration ---

print_header "Step 3: Configuring suricata.yaml and System Service"
SURICATA_CONF="/etc/suricata/suricata.yaml"
SURICATA_DEFAULTS="/etc/default/suricata"

# Backup the original configuration file
cp "$SURICATA_CONF" "${SURICATA_CONF}.bak.$(date +%s)"
echo "Backed up original YAML configuration to ${SURICATA_CONF}.bak.<timestamp>"

# Set HOME_NET
echo "Setting HOME_NET to [$HOME_NET]..."
sed -i "s|^\(\s*HOME_NET:\s*\)\"\[.*\]\"|\1\"[$HOME_NET]\"|g" "$SURICATA_CONF"

# In IPS mode, Suricata handles traffic capture via NFQUEUE, not a specific interface.
# The 'interface' setting in the yaml should be 'default'
echo "Setting interface in suricata.yaml to 'default' for IPS mode..."
sed -i -e "s/^    - interface: .*/    - interface: default/" "$SURICATA_CONF"

# Configure the systemd service to use NFQUEUE mode. This is the correct way.
echo "Configuring system service for NFQUEUE (IPS) mode..."
if [ -f "$SURICATA_DEFAULTS" ]; then
    # Modify the LISTENMODE for the service
    sed -i 's/^LISTENMODE=.*/LISTENMODE=nfqueue/' "$SURICATA_DEFAULTS"
else
    # If the defaults file doesn't exist, create it
    echo 'LISTENMODE=nfqueue' > "$SURICATA_DEFAULTS"
fi

# Ensure log directory exists and has correct permissions
echo "Ensuring correct log directory permissions..."
mkdir -p /var/log/suricata
chown -R suricata:suricata /var/log/suricata

echo "Configuration updated."


# --- Validation ---

print_header "Step 4: Validating Suricata Configuration"
echo "Running a pre-flight test on the configuration and rules..."
if ! /usr/bin/suricata -T -c "$SURICATA_CONF" -v; then
    exit_with_error "Suricata configuration test failed. Please review the errors above."
fi
echo "Configuration and rules validated successfully."


# --- Firewall Setup & Service Start ---

print_header "Step 5: Applying Firewall Rules and Starting Suricata"

# Function to clean up iptables rules on failure
cleanup_on_failure() {
    echo " "
    echo "‼️ An error occurred. Rolling back firewall rules to restore connectivity..."
    iptables -F
    echo "iptables rules flushed. Network should be restored."
}

# Trap errors to call the cleanup function. This is our safety net.
trap cleanup_on_failure ERR

# Flush any existing rules to be safe
iptables -F

# Add bypass rules FIRST for stability
iptables -I INPUT 1 -i lo -j ACCEPT
iptables -I OUTPUT 1 -o lo -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Send NEW connections to NFQUEUE for Suricata to inspect
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
iptables -A FORWARD -j NFQUEUE --queue-num 0

echo "iptables rules added. Note: These are not persistent across reboots."

# Stop any running instance and clean up the old PID file
systemctl stop suricata
rm -f /var/run/suricata.pid # Remove stale PID file

# Reload systemd to pick up changes in /etc/default
systemctl daemon-reload
echo "Starting Suricata service..."
systemctl start suricata

# Verify that the service has started
echo "Waiting for Suricata engine to initialize..."
SURICATA_LOG="/var/log/suricata/suricata.log"

# Wait up to 30 seconds for the engine to start
for i in {1..30}; do
    # Check if the service is active AND has initialized NFQUEUE mode in the log
    if systemctl is-active --quiet suricata && grep -q "NFQ running in IPS mode" "$SURICATA_LOG"; then
        echo "✅ Suricata service is active and running in IPS mode."
        trap - ERR # Disable the error trap if we succeed
        break
    fi

    if [ "$i" -eq 30 ]; then # If we hit the 30-second mark, it failed
        echo "Timed out waiting for Suricata to start."
        if ! systemctl is-active --quiet suricata; then
            exit_with_error "Suricata service is not active. Check 'systemctl status suricata' and 'journalctl -u suricata'."
        else
            exit_with_error "Suricata service is active, but failed to initialize IPS mode. Check logs at $SURICATA_LOG"
        fi
    fi
    sleep 1
done

# --- Test ---

print_header "Step 6: Running Live Test"

# Perform the test
echo "Running test with curl http://testmynids.org/uid/index.html..."
echo "A successful IPS block will cause this command to hang or fail."
curl --max-time 10 http://testmynids.org/uid/index.html

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

# Config JA4 fingerprinting/logging in config YAML
echo "Configuring JA4 fingerprinting/logging..."
sed -i 's/# ja4: off/ja4: on/g' $SURICATA_CONF
sed -i 's/#ja3-fingerprints\: auto/ja3-fingerprints\: auto/g' $SURICATA_CONF
sed -i 's/#ja4-fingerprints\: auto/ja4-fingerprints\: auto/g' $SURICATA_CONF
sed -i 's/#encryption-handling\: default/encryption-handling\: default/g' $SURICATA_CONF

print_header "Setup Complete"
echo "To see live alerts, run: tail -f /var/log/suricata/fast.log"
echo "To stop Suricata, run: systemctl stop suricata && iptables -F"
