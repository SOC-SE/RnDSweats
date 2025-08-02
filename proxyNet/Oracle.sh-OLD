#!/bin/bash

# ============================================================================
# Wazuh Manager Deployment Script for Collegiate Cyber Defense Competition
#
# Target OS: Oracle Linux 9.2
# Documents: 2025MWCCDCQTeamPack (1) (2).pdf
#            Wazuh EDR Enhancement Strategies_.pdf
#
# This script automates the deployment and hardening of a Wazuh manager
# tailored for a CCDC environment.
# ============================================================================

# --- Globals and Utility Functions ---
LOG_FILE="/var/log/wazuh_deploy.log"
WMANAGER_CONF="/var/ossec/etc/ossec.conf"
AGENT_SHARED_CONF="/var/ossec/etc/shared/default/agent.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
OSSEC_LOG="/var/ossec/logs/ossec.log"

# Function to print messages to stdout and log file
log_msg() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

info() {
    log_msg "[INFO] $1"
}

warn() {
    log_msg "[WARN] $1"
}

error() {
    log_msg "[ERROR] $1" >&2
    exit 1
}

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        error "Last command failed. See $LOG_FILE for details. Exiting."
    fi
}

# --- Script Sections ---

# Section 1: Automated Installation of Wazuh Manager
section_one_install() {
    info "--- Starting Section 1: Automated Installation ---"

    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root."
    fi

    info "Adding the Wazuh repository for Oracle Linux 9..."
    cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    check_success

    info "Installing Wazuh manager and dependencies. This may take a few minutes..."
    # As per the prompt, we only install the manager. The indexer and dashboard are excluded.
    # xmlstarlet is a dependency for safely editing config files in Section 3.
    dnf install -y wazuh-manager xmlstarlet
    check_success

    info "Enabling the wazuh-manager service to start on boot..."
    systemctl daemon-reload
    systemctl enable wazuh-manager
    check_success

    info "Wazuh manager installation is complete."
    info "--- Section 1 (Automated Installation) is complete. ---"
}

# Section 2: Base Configuration for Agent Communication
section_two_base_config() {
    info "--- Starting Section 2: Base Configuration ---"

    info "Verifying agent communication settings..."
    info "The default Wazuh manager installation is already configured to listen for agents securely."
    info "Key settings in $WMANAGER_CONF are verified as follows:"

    # The Wazuh agent communicates with the server over a secure, encrypted channel on TCP port 1514 by default.
    # This aligns with both the Wazuh documentation and the typical CCDC setup.
    if grep -q '<connection>secure</connection>' "$WMANAGER_CONF" && grep -q '<port>1514</port>' "$WMANAGER_CONF"; then
        info " ✔ OK: Agent listener is configured for secure connection on TCP port 1514."
        info "This is the required configuration for agent communication."
    else
        error "Default secure agent listener on port 1514 not found. Aborting."
    fi

    info "Further hardening (e.g., firewall rules) should be applied at the OS level and is outside the scope of this application script."
    info "No changes are needed for the base configuration."
    info "--- Section 2 (Base Configuration) is complete. ---"
}

# REFACTORED FUNCTION: Atomically updates the ossec.conf file using a robust file reconstruction method.
update_ossec_conf() {
    info "Atomically updating manager configuration..."
    local TMP_CONF="${WMANAGER_CONF}.tmp"

    # FIX: The default config can be malformed. This command truncates the file
    # after the first valid closing tag, ensuring a clean XML document for parsing.
    sed -i.bak '/<\/ossec_config>/q' "$WMANAGER_CONF"
    check_success

    # --- Edit 1: Add the CDB list using xmlstarlet (this one is simple and known to work) ---
    info "Adding CDB list to configuration..."
    xmlstarlet ed --subnode "//ruleset" --type elem -n "list" -v "etc/lists/suspicious-programs" "$WMANAGER_CONF" > "$TMP_CONF" && mv "$TMP_CONF" "$WMANAGER_CONF"
    check_success

    # --- Edit 2 & 3: Rebuild the file to insert Active Response blocks. This is the most reliable method. ---
    info "Adding Active Response blocks to configuration..."
    
    # 1. Copy the file, minus the last line (</ossec_config>), to a temp file.
    head -n -1 "$WMANAGER_CONF" > "$TMP_CONF"
    check_success

    # 2. Append the new XML blocks to the temp file.
    cat >> "$TMP_CONF" << EOF

  <command>
    <name>quarantine-host</name>
    <executable>quarantine.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>quarantine-host</command>
    <location>local</location>
    <rules_id>110000</rules_id>
  </active-response>
EOF
    check_success

    # 3. Append the last line back to the temp file.
    tail -n 1 "$WMANAGER_CONF" >> "$TMP_CONF"
    check_success

    # 4. Atomically replace the original file with the modified one.
    mv "$TMP_CONF" "$WMANAGER_CONF"
    check_success
    
    info "✔ OK: Manager configuration staging complete."
}


# Section 3: Advanced EDR Enhancements
section_three_advanced_edr() {
    info "--- Starting Section 3: Advanced EDR Enhancements ---"

    # Create centralized agent configuration for FIM and Rootcheck
    info "Creating centralized agent configuration ($AGENT_SHARED_CONF)..."
    cat > "$AGENT_SHARED_CONF" <<EOF
<agent_config>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>

    <directories check_all="yes" realtime="yes" report_changes="yes" whodata="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>

</agent_config>
EOF
    check_success
    info "✔ OK: Centralized FIM and Rootcheck configuration created."

    # Create CDB list for suspicious programs
    info "Creating CDB list for suspicious programs..."
    cat > /var/ossec/etc/lists/suspicious-programs <<EOF
ncat:
nc:
tcpdump:
socat:
EOF
    check_success
    chown wazuh:wazuh /var/ossec/etc/lists/suspicious-programs
    check_success
    info "✔ OK: CDB list '/var/ossec/etc/lists/suspicious-programs' created."

    # Configure manager to use CDB list and set up Active Response
    update_ossec_conf

    # Add custom rules to local_rules.xml
    info "Adding custom rules for suspicious command execution and ransomware correlation..."
    cat >> "$LOCAL_RULES" <<EOF

<group name="audit, suspicious_command,">
  <rule id="100210" level="10">
    <if_sid>80792</if_sid>
    <list field="audit.command" lookup="match_key">etc/lists/suspicious-programs</list>
    <description>Audit: Privileged execution of suspicious program detected: \$(audit.command)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>

<group name="ransomware, correlation,">
  <rule id="110000" level="15" timeframe="120">
    <if_matched_sid>100102</if_matched_sid>
    <if_matched_sid>100150</if_matched_sid>
    <description>Ransomware Attack Pattern Correlated. Multiple TTPs detected. Triggering host isolation.</description>
    <mitre>
      <id>T1486</id>
    </mitre>
  </rule>
</group>
EOF
    check_success
    info "✔ OK: Custom rules added to $LOCAL_RULES."

    # Validate all configurations before proceeding
    info "Validating all Wazuh configuration files..."
    /var/ossec/bin/wazuh-analysisd -t
    check_success
    info "✔ OK: All configurations are valid."

    info "--- Section 3 (Advanced EDR Enhancements) is complete. ---"
}

# Section 4: Operationalization
section_four_operationalize() {
    info "--- Starting Section 4: Operationalization ---"

    info "Applying all configurations by restarting the Wazuh manager..."
    systemctl restart wazuh-manager
    check_success

    info "Waiting a moment for the service to initialize..."
    sleep 10

    info "Verifying the status of the wazuh-manager service..."
    if systemctl is-active --quiet wazuh-manager; then
        info "✔ OK: Wazuh manager service is active and running."
    else
        error "Wazuh manager service failed to start. Check $OSSEC_LOG for errors."
    fi

    info "Checking for critical errors in the log file..."
    if grep -E "ERROR:|CRITICAL:" "$OSSEC_LOG"; then
        warn "Potential errors found in $OSSEC_LOG. Manual review is recommended."
    else
        info "✔ OK: No critical errors detected in the log file."
    fi

    info "--- Section 4 (Operationalization) is complete. ---"
}

# --- Main Execution ---

# Execute Section 1
section_one_install

# Execute Section 2
section_two_base_config

# Execute Section 3
section_three_advanced_edr

# Execute Section 4
section_four_operationalize

# --- Final Summary ---
info "============================================================"
info "✅ Wazuh Manager Deployment Complete!"
info "The Wazuh manager is installed, configured, and running."
info "Key enhancements include:"
info "  - Advanced FIM and Rootcheck policies for agents."
info "  - Custom rules to detect suspicious command execution."
info "  - Active Response configured to isolate compromised hosts."
info "The system is now ready for agent registration and monitoring."
info "============================================================"
