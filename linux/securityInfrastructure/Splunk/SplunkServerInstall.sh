#!/bin/bash
set -euo pipefail
# ==============================================================================
# Script Name: SplunkServerInstall.sh
# Description: Distro-agnostic Splunk Enterprise install script.
#              Backs up licenses, nukes old install, installs fresh,
#              restores licenses, sets up admin user, configures inputs.conf
#              (syslog listeners + local log monitors), props.conf, transforms.conf,
#              enables 9997 forwarder receiver, installs dashboards,
#              and optionally installs add-ons from Splunkbase.
# Author: Samuel Brucker 2024-2026
# Version: 3.0
#
# Supported Systems:
#   - Ubuntu/Debian (apt, .deb)
#   - Fedora/RHEL/Oracle/Rocky/Alma (dnf/yum, .rpm)
#
# Usage:
#   sudo ./SplunkServerInstall.sh
#
# Environment Variables (optional, will prompt if not set):
#   SPLUNK_PASS      - Splunk admin password
#   SPLUNKBASE_USER  - Splunkbase username (email) for add-on installation
#   SPLUNKBASE_PASS  - Splunkbase password
#
# ==============================================================================

# --- Configuration ---
SPLUNK_VERSION="10.0.2"
SPLUNK_BUILD="e2d18b4767e9"
SPLUNK_HOME="/opt/splunk"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root"
    exit 1
fi

# --- Detect distro and set package info ---
if command -v dnf &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="yum"
elif command -v apt-get &>/dev/null; then
    DISTRO="debian"
    PKG_MGR="apt-get"
else
    echo "[ERROR] No supported package manager found (dnf, yum, apt-get)"
    exit 1
fi

if [[ "$DISTRO" == "rhel" ]]; then
    SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
else
    SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.deb"
fi
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PKG}"

# --- Prompt for Splunk admin password ---
if [[ -z "${SPLUNK_PASS:-}" ]]; then
    while true; do
        echo -n "Enter password for Splunk admin user: "
        stty -echo
        read -r pass1
        stty echo
        echo
        echo -n "Confirm password: "
        stty -echo
        read -r pass2
        stty echo
        echo
        if [[ "$pass1" == "$pass2" ]] && [[ -n "$pass1" ]]; then
            SPLUNK_PASS="$pass1"
            break
        else
            echo "Passwords do not match or are empty. Please try again."
        fi
    done
fi

# --- Handle existing installation ---
BACKUP_DIR="/home/splbackup"
if [[ -d "$SPLUNK_HOME" ]]; then
    echo "Splunk is already installed at $SPLUNK_HOME."
    read -r -p "Completely DELETE and reinstall Splunk? (y/N): " choice
    case "$choice" in
        [yY]|[yY][eE][sS])
            echo "Stopping and removing old Splunk..."
            $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
            $SPLUNK_HOME/bin/splunk disable boot-start 2>/dev/null || true
            pkill -f splunkd 2>/dev/null || true

            # Backup licenses
            mkdir -p "$BACKUP_DIR"
            if [[ -d "$SPLUNK_HOME/etc/licenses" ]]; then
                cp -R "$SPLUNK_HOME/etc/licenses/." "$BACKUP_DIR/" 2>/dev/null || true
                echo "Licenses backed up to $BACKUP_DIR"
            fi

            # Remove package and directory
            if [[ "$DISTRO" == "rhel" ]]; then
                $PKG_MGR remove -y splunk 2>/dev/null || rpm -e splunk 2>/dev/null || true
            else
                apt-get purge -y splunk 2>/dev/null || dpkg -r splunk 2>/dev/null || true
            fi
            rm -rf "$SPLUNK_HOME"
            echo "Old Splunk removed."
            ;;
        *)
            echo "Aborting. Splunk was not changed."
            exit 0
            ;;
    esac
fi

# --- Install prerequisites (RHEL) ---
if [[ "$DISTRO" == "rhel" ]]; then
    echo "Installing prerequisites..."
    $PKG_MGR install -y libxcrypt-compat 2>/dev/null || true
fi

# --- Download Splunk ---
echo "Downloading Splunk $SPLUNK_VERSION..."
if ! wget -q -O "$SPLUNK_PKG" "$SPLUNK_URL"; then
    echo "[ERROR] Failed to download Splunk. Exiting."
    exit 1
fi

# --- Install Splunk ---
echo "Installing Splunk $SPLUNK_VERSION..."
if [[ "$DISTRO" == "rhel" ]]; then
    $PKG_MGR install -y "./$SPLUNK_PKG" 2>/dev/null || rpm -i "$SPLUNK_PKG"
else
    DEBIAN_FRONTEND=noninteractive apt-get install -y "./$SPLUNK_PKG" 2>/dev/null || dpkg -i "$SPLUNK_PKG"
fi
rm -f "$SPLUNK_PKG"

# --- Create admin user via seed ---
echo "Creating admin user..."
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/user-seed.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"

# --- Install custom props.conf if available ---
PROPS_CONF=""
for props_path in "$SCRIPT_DIR/props.conf" "/tmp/props.conf"; do
    if [[ -f "$props_path" ]]; then
        PROPS_CONF="$props_path"
        break
    fi
done

if [[ -n "$PROPS_CONF" ]]; then
    echo "Installing custom props.conf from $PROPS_CONF..."
    cp "$PROPS_CONF" "$SPLUNK_HOME/etc/system/local/props.conf"
    chown splunk:splunk "$SPLUNK_HOME/etc/system/local/props.conf"
else
    echo "[WARN] props.conf not found, skipping."
fi

# --- Install custom transforms.conf if available ---
TRANSFORMS_CONF=""
for transforms_path in "$SCRIPT_DIR/transforms.conf" "/tmp/transforms.conf"; do
    if [[ -f "$transforms_path" ]]; then
        TRANSFORMS_CONF="$transforms_path"
        break
    fi
done

if [[ -n "$TRANSFORMS_CONF" ]]; then
    echo "Installing custom transforms.conf from $TRANSFORMS_CONF..."
    cp "$TRANSFORMS_CONF" "$SPLUNK_HOME/etc/system/local/transforms.conf"
    chown splunk:splunk "$SPLUNK_HOME/etc/system/local/transforms.conf"
else
    echo "[WARN] transforms.conf not found, skipping."
fi

# --- Configure inputs.conf (listeners + local log monitors) ---
echo "Configuring inputs.conf..."
cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'INPUTS_EOF'
[default]
host = $decideOnStartup

# =============================================================================
# Network listeners (syslog from firewalls, DNS)
# =============================================================================

[tcp://514]
sourcetype = palo
index = network
disabled = 0

[udp://514]
sourcetype = cisco
index = network
disabled = 0

[tcp://5140]
sourcetype = technitium:query
index = network
disabled = 0
connection_host = ip

# =============================================================================
# Local file monitors (logs generated on this host)
# =============================================================================

# --- System logs ---

[monitor:///var/log/auth.log]
index = linux
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/secure]
index = linux
sourcetype = linux_secure
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/messages]
index = linux
sourcetype = syslog
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

[monitor:///var/log/audit/audit.log]
index = linux
sourcetype = linux:audit
crcSalt = <SOURCE>
blacklist = \.(gz|bz2|zip)$|\.\d$

# --- Custom scripts (syst) ---

[monitor:///var/log/syst/*audit*]
index = linux
sourcetype = linux_enum
crcSalt = <SOURCE>

[monitor:///var/log/syst/security_scan_*.log]
index = linux
sourcetype = linux_security_scan
crcSalt = <SOURCE>

[monitor:///var/log/syst/linpeas_findings_*.log]
index = linux
sourcetype = linpeas
crcSalt = <SOURCE>

[monitor:///var/log/syst/integrity_scan.log]
index = linux
sourcetype = linux_rootkit
crcSalt = <SOURCE>

[monitor:///var/log/syst/pre_install_compromise.log]
index = linux
sourcetype = linux_rootkit
crcSalt = <SOURCE>

# --- LMD (Linux Malware Detect) ---

[monitor:///usr/local/maldetect/logs/event_log]
index = linux
sourcetype = linux_av:events
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/logs/scan_log]
index = linux
sourcetype = linux_av:scan_summaries
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/logs/error_log]
index = linux
sourcetype = linux_av:errors
crcSalt = <SOURCE>

[monitor:///usr/local/maldetect/sess/*]
index = linux
sourcetype = linux_av:full_reports
crcSalt = <SOURCE>

# --- Wazuh (local manager logs) ---

[monitor:///var/ossec/logs/ossec.log]
index = linux
sourcetype = wazuh:agent
crcSalt = <SOURCE>

[monitor:///var/ossec/logs/api.log]
index = linux
sourcetype = wazuh:api
crcSalt = <SOURCE>

[monitor:///var/ossec/logs/alerts/alerts.json]
index = linux
sourcetype = wazuh:alerts
crcSalt = <SOURCE>
disabled = 0

# --- Salt Master ---

[monitor:///var/log/salt/master]
index = linux
sourcetype = salt:master
crcSalt = <SOURCE>

# --- Technitium DNS (Docker container, host-mounted volume) ---

[monitor:///opt/technitium-dns/config/logs/*.log]
index = linux
sourcetype = technitium:syslog
crcSalt = <SOURCE>

# --- Honeypot (Cowrie SSH/Telnet) ---

[monitor:///opt/cowrie/var/log/cowrie/cowrie.json]
index = linux
sourcetype = cowrie
crcSalt = <SOURCE>

[monitor:///opt/cowrie/var/log/cowrie/cowrie.log]
index = linux
sourcetype = cowrie:text
crcSalt = <SOURCE>
INPUTS_EOF

# Replace $decideOnStartup with actual hostname
sed -i "s/\$decideOnStartup/$(hostname)/" "$SPLUNK_HOME/etc/system/local/inputs.conf"
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/inputs.conf"
echo "inputs.conf configured (syslog listeners + local log monitors)"

# --- Lock down MongoDB/KVStore to localhost ---
echo "Locking down KVStore to localhost..."
if [[ -f "$SPLUNK_HOME/etc/system/local/server.conf" ]]; then
    # Append kvstore section if not already present
    if ! grep -q '\[kvstore\]' "$SPLUNK_HOME/etc/system/local/server.conf"; then
        printf '\n[kvstore]\nserverAddress = 127.0.0.1\n' >> "$SPLUNK_HOME/etc/system/local/server.conf"
    fi
else
    cat > "$SPLUNK_HOME/etc/system/local/server.conf" <<EOF
[kvstore]
serverAddress = 127.0.0.1
EOF
fi
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/server.conf"

# --- Restore backed up licenses ---
if [[ -d "$BACKUP_DIR" ]] && [[ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
    echo "Restoring licenses..."
    mkdir -p "$SPLUNK_HOME/etc/licenses"
    cp -r "$BACKUP_DIR/." "$SPLUNK_HOME/etc/licenses/"
    chown -R splunk:splunk "$SPLUNK_HOME/etc/licenses"
fi

# --- Install add-ons (before first start) ---
ADDONS_DIR=""
for addon_path in "$SCRIPT_DIR/Addons" "/tmp/Addons"; do
    if [[ -d "$addon_path" ]]; then
        ADDONS_DIR="$addon_path"
        break
    fi
done

if [[ -n "$ADDONS_DIR" ]]; then
    echo "Installing add-ons from $ADDONS_DIR..."
    for addon in "$ADDONS_DIR"/*.tgz; do
        [[ -f "$addon" ]] || continue
        tar -xzf "$addon" -C "$SPLUNK_HOME/etc/apps/"
        echo "  Installed $(basename "$addon")"
    done
    chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/"
else
    echo "[INFO] No Addons directory found, skipping add-on installation."
fi

# --- Start Splunk ---
echo "Starting Splunk and accepting license..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

$SPLUNK_HOME/bin/splunk add index linux -auth "admin:$SPLUNK_PASS" || echo "[WARN] Index 'linux' may already exist"
$SPLUNK_HOME/bin/splunk add index windows -auth "admin:$SPLUNK_PASS" || echo "[WARN] Index 'windows' may already exist"
$SPLUNK_HOME/bin/splunk add index network -auth "admin:$SPLUNK_PASS" || echo "[WARN] Index 'network' may already exist"

# --- Enable forwarder receiver on port 9997 ---
echo "Enabling forwarder listener on port 9997..."
$SPLUNK_HOME/bin/splunk enable listen 9997 -auth "admin:$SPLUNK_PASS"

# --- Install dashboards ---
DASHBOARD_DIR=""
for dash_path in "$SCRIPT_DIR/Dashboards" "/tmp/Dashboards"; do
    if [[ -d "$dash_path" ]]; then
        DASHBOARD_DIR="$dash_path"
        break
    fi
done

if [[ -n "$DASHBOARD_DIR" ]]; then
    echo "Installing dashboards from $DASHBOARD_DIR..."
    VIEWS_DIR="$SPLUNK_HOME/etc/apps/search/local/data/ui/views"
    mkdir -p "$VIEWS_DIR"

    for xml_file in "$DASHBOARD_DIR"/*.xml; do
        [[ -f "$xml_file" ]] || continue
        cp "$xml_file" "$VIEWS_DIR/"
        echo "  Installed $(basename "$xml_file")"
    done

    chown -R splunk:splunk "$VIEWS_DIR"
    echo "Dashboards installed to $VIEWS_DIR"
else
    echo "[WARN] Dashboards directory not found, skipping."
fi

echo "Enabling boot start..."
$SPLUNK_HOME/bin/splunk enable boot-start --accept-license --answer-yes --no-prompt

# --- Install add-ons from Splunkbase ---
# Splunkbase app definitions: "APP_ID|APP_NAME|DESCRIPTION"
SPLUNKBASE_ADDONS=(
    "2757|Splunk_TA_paloalto|Palo Alto Networks"
    "4388|Splunk_TA_cisco_secure_firewall|Cisco Secure Firewall (FTD)"
    "5466|TA-zeek|Zeek"
    "2760|TA-suricata|Suricata"
    "742|Splunk_TA_windows|Windows"
    "5709|Splunk_TA_microsoft_sysmon|Sysmon"
    "3208|Splunk_TA_microsoft-dns|Microsoft Windows DNS"
    "833|Splunk_TA_nix|Unix and Linux"
    "4494|SplunkAppForWazuh|Wazuh"
    "3186|Splunk_TA_apache|Apache Web Server"
    "3258|Splunk_TA_nginx|NGINX"
    "2891|TA-haproxy|HAProxy"
    "5765|Splunk_TA_docker|Docker"
    "1917|splunk_app_for_tomcat|Tomcat"
    "4679|Splunk_TA_postgresql|PostgreSQL"
    "2818|Splunk_TA_mysql|MySQL"
    "1621|Splunk_SA_CIM|Common Information Model (CIM)"
)

echo ""
echo "========================================================"
echo "  Splunkbase Add-on Installation"
echo "========================================================"
echo "This will install ${#SPLUNKBASE_ADDONS[@]} recommended add-ons for:"
echo "  - Network devices (Palo Alto, Cisco FTD, Zeek, Suricata)"
echo "  - Windows (Event logs, Sysmon, DNS)"
echo "  - Linux/Unix, Web servers, Databases, Containers"
echo ""
read -r -p "Install add-ons from Splunkbase? (Y/n): " INSTALL_ADDONS
case "$INSTALL_ADDONS" in
    [nN]|[nN][oO])
        echo "Skipping Splunkbase add-on installation."
        ;;
    *)
        # Prompt for Splunkbase credentials
        echo ""
        if [[ -z "${SPLUNKBASE_USER:-}" ]]; then
            echo -n "Enter Splunkbase username (email): "
            read -r SPLUNKBASE_USER
        fi
        if [[ -z "${SPLUNKBASE_PASS:-}" ]]; then
            echo -n "Enter Splunkbase password: "
            stty -echo
            read -r SPLUNKBASE_PASS
            stty echo
            echo ""
        fi

        echo ""
        echo "Installing add-ons from Splunkbase..."
        ADDON_SUCCESS=0
        ADDON_FAIL=0
        ADDON_SKIP=0

        for addon in "${SPLUNKBASE_ADDONS[@]}"; do
            IFS='|' read -r app_id app_name description <<< "$addon"
            printf "  %-40s " "$description..."

            # Check if already installed
            CHECK=$(curl -s -k -u "admin:${SPLUNK_PASS}" \
                "https://localhost:8089/services/apps/local/${app_name}?output_mode=json" 2>/dev/null)

            if echo "$CHECK" | grep -q '"name"'; then
                echo "SKIP (already installed)"
                ((ADDON_SKIP++))
                continue
            fi

            # Install from Splunkbase
            INSTALL_RESPONSE=$(curl -s -k -w "\n%{http_code}" \
                -u "admin:${SPLUNK_PASS}" \
                -X POST \
                -d "name=${app_name}" \
                -d "auth=${SPLUNKBASE_USER}:${SPLUNKBASE_PASS}" \
                -d "update=true" \
                "https://localhost:8089/services/apps/local" 2>/dev/null)

            HTTP_CODE=$(echo "$INSTALL_RESPONSE" | tail -1)
            RESPONSE_BODY=$(echo "$INSTALL_RESPONSE" | sed '$d')

            if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "201" ]]; then
                echo "OK"
                ((ADDON_SUCCESS++))
            elif echo "$RESPONSE_BODY" | grep -qi "already exists"; then
                echo "SKIP (already installed)"
                ((ADDON_SKIP++))
            else
                ERROR_MSG=$(echo "$RESPONSE_BODY" | grep -oP '"message"\s*:\s*"\K[^"]+' | head -1)
                echo "FAILED (${ERROR_MSG:-HTTP $HTTP_CODE})"
                ((ADDON_FAIL++))
            fi

            sleep 1
        done

        echo ""
        echo "Add-on installation complete:"
        echo "  Installed: $ADDON_SUCCESS"
        echo "  Skipped:   $ADDON_SKIP"
        echo "  Failed:    $ADDON_FAIL"
        ;;
esac

# Restart to load all configurations and add-ons
echo ""
echo "Restarting Splunk to load all configurations..."
$SPLUNK_HOME/bin/splunk restart

echo ""
echo "========================================================"
echo "  Splunk $SPLUNK_VERSION installation complete!"
echo "  Web UI: https://localhost:8000"
echo "  Forwarder receiver: port 9997"
echo "  Syslog listeners: tcp/514, udp/514, tcp/5140"
echo "  Dashboards: Settings > Dashboards, or search 'CCDC'"
echo "========================================================"
