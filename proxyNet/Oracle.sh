#!/bin/bash

# ============================================================================
# Wazuh Manager Deployment Script for Collegiate Cyber Defense Competition
#
# Target OS: Oracle Linux 9.2
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
    dnf install -y wazuh-manager; check_success

    info "Enabling the wazuh-manager service to start on boot..."
    systemctl daemon-reload; check_success
    systemctl enable wazuh-manager; check_success

    info "Wazuh manager installation is complete."
    info "--- Section 1 (Automated Installation) is complete. ---"
}

# Section 2: Base Configuration for Agent Communication
section_two_base_config() {
    info "--- Starting Section 2: Base Configuration ---"
    info "Verifying agent communication settings..."

    if grep -q '<connection>secure</connection>' "$WMANAGER_CONF" && grep -q '<port>1514</port>' "$WMANAGER_CONF"; then
        info " ✔ OK: Agent listener is configured for secure connection on TCP port 1514."
    else
        error "Default secure agent listener on port 1514 not found. Aborting."
    fi

    info "--- Section 2 (Base Configuration) is complete. ---"
}

# Section 3: Advanced EDR Enhancements
section_three_advanced_edr() {
    info "--- Starting Section 3: Advanced EDR Enhancements ---"

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

    info "Creating CDB list for suspicious programs..."
    cat > /var/ossec/etc/lists/suspicious-programs <<EOF
ncat:
nc:
tcpdump:
socat:
EOF
    check_success
    chown wazuh:wazuh /var/ossec/etc/lists/suspicious-programs; check_success
    info "✔ OK: CDB list '/var/ossec/etc/lists/suspicious-programs' created."

    info "Configuring manager to use CDB list and Active Response using sed..."

    # Define the XML blocks to be inserted
    read -r -d '' BLOCKS_TO_INSERT << EOM
  <ruleset>
    <list>etc/lists/suspicious-programs</list>
  </ruleset>

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
EOM

    # Use grep to check for a unique part of the block to ensure idempotency
    if ! grep -q "quarantine-host" "$WMANAGER_CONF"; then
        # Insert the blocks just before the final </ossec_config> tag
        sed -i "/<\/ossec_config>/i $BLOCKS_TO_INSERT" "$WMANAGER_CONF"; check_success
        info "✔ OK: Added CDB list, command, and active-response blocks to ossec.conf."
    else
        warn "Active Response configurations already found in ossec.conf. Skipping."
    fi

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
    <if_matched_sid>100102</if_matched_sid> <if_matched_sid>100150</if_matched_sid> <description>Ransomware Attack Pattern Correlated. Multiple TTPs detected. Triggering host isolation.</description>
    <mitre>
      <id>T1486</id>
    </mitre>
  </rule>
</group>
EOF
    check_success
    info "✔ OK: Custom rules added to $LOCAL_RULES."
    info "--- Section 3 (Advanced EDR Enhancements) is complete. ---"
}

# Section 4: Operationalization
section_four_operationalize() {
    info "--- Starting Section 4: Operationalization ---"

    info "Applying all configurations by restarting the Wazuh manager..."
    systemctl restart wazuh-manager; check_success

    info "Waiting a moment for the service to initialize..."
    sleep 10

    info "Verifying the status of the wazuh-manager service..."
    if systemctl is-active --quiet wazuh-manager; then
        info "✔ OK: Wazuh manager service is active and running."
    else
        error "Wazuh manager service failed to start. Check $OSSEC_LOG for errors."
    fi

    info "Checking for critical errors in the log file..."
    if grep -q -E "ERROR:|CRITICAL:" "$OSSEC_LOG"; then
        warn "Potential errors found in $OSSEC_LOG. Manual review is recommended."
    else
        info "✔ OK: No critical errors detected in the log file."
    fi

    info "--- Section 4 (Operationalization) is complete. ---"
}

# --- Main Execution ---
section_one_install
section_two_base_config
section_three_advanced_edr
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
