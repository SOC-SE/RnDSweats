#!/bin/bash
# Exit immediately if a command exits with a non-zero status or on pipe failures.
set -eo pipefail

# --- Script Configuration ---
# CHANGED: Paths are now absolute and in standard system locations.
CONFIG_ROOT="/etc/suricata"
LOGS_ROOT="/var/log/suricata"

DOCKER_COMPOSE_FILE="docker-compose.yml" # This file is temporary and stays local
CONFIG_DIR="${CONFIG_ROOT}"
RULES_DIR="${CONFIG_ROOT}/rules"
LOGS_DIR="${LOGS_ROOT}"
SURICATA_YAML="${CONFIG_DIR}/suricata.yaml"

# --- Main Functions ---

# Clean up old iptables rules and containers to ensure a clean slate
cleanup_previous_run() {
    echo "Checking for and removing leftover iptables rules..."
    # Use || true to prevent the script from exiting if the rule doesn't exist
    sudo iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true

    if [ -f ${DOCKER_COMPOSE_FILE} ]; then
        echo "Stopping any previously running suricata container..."
        sudo docker-compose down --remove-orphans 2>/dev/null || true
    fi
    echo "System is clean."
}

# 1. Check for Docker and Docker Compose
check_dependencies() {
    echo "Checking for Docker and Docker Compose..."
    if ! command -v docker &> /dev/null; then echo "❌ Docker not found!"; exit 1; fi
    if ! command -v docker-compose &> /dev/null; then echo "❌ Docker Compose not found!"; exit 1; fi
    echo "Dependencies are satisfied."
}

# 2. Prompt user to select a network interface
select_interface() {
    echo "Please select the network interface you want Suricata to protect:"
    interfaces=($(ls /sys/class/net | grep -v "lo"))
    select interface in "${interfaces[@]}"; do
        if [[ -n "$interface" ]]; then
            echo "You have selected: $interface"
            MONITORED_INTERFACE=$interface
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done
}

# 3. Create directories, download rules, and generate the complete config
setup_environment() {
    echo "Setting up directories..."
    # ADDED: sudo is required to write to /etc/ and /var/log/
    sudo mkdir -p "${CONFIG_DIR}" "${RULES_DIR}" "${LOGS_DIR}"

    echo "Generating the default suricata.yaml configuration file..."
    # CHANGED: Must use sudo tee to write to the protected file
    sudo docker run --rm jasonish/suricata:latest cat /etc/suricata/suricata.yaml | sudo tee "${SURICATA_YAML}" > /dev/null

    echo "Modifying suricata.yaml for IPS mode and network settings..."
    # ADDED: sudo is required to modify files in /etc/
    sudo sed -i "/af-packet:/,/threads: auto/ s/#   - interface: default/  - interface: ${MONITORED_INTERFACE}/" "${SURICATA_YAML}"
    sudo sed -i 's/checksum-validation: yes/checksum-validation: no/' "${SURICATA_YAML}"
    sudo sed -i 's/#nfq:/nfq:/' "${SURICATA_YAML}"

    echo "Downloading and processing rulesets with suricata-update..."
    # This command already uses sudo and mounts the correct new volume
    sudo docker run --rm \
      -v "${RULES_DIR}:/var/lib/suricata/rules" \
      jasonish/suricata:latest \
      sh -c " \
        suricata-update enable-source ptresearch/attackdetection && \
        suricata-update enable-source oisf/trafficid && \
        suricata-update enable-source sslbl/ja3-fingerprints && \
        echo '--> All sources enabled. Now fetching rules...' && \
        suricata-update \
      "
    
    echo "Converting all 'alert' rules to 'drop' using sed..."
    # This command already uses sudo
    if [ -f "${RULES_DIR}/suricata.rules" ]; then
        sudo sed -i 's/^alert/drop/' "${RULES_DIR}/suricata.rules"
        echo "All rules converted to drop."
    else
        echo "Error: ${RULES_DIR}/suricata.rules not found after update!"
        exit 1
    fi

    echo "Environment is ready with multiple rulesets configured to drop."
}

# 4. Create the Docker Compose file
create_docker_compose() {
    echo "Creating Docker Compose file..."
# CHANGED: The volumes section now uses the absolute path variables
cat << EOF > ${DOCKER_COMPOSE_FILE}
version: '3.3'
services:
  suricata:
    image: jasonish/suricata:latest
    container_name: suricata
    restart: always
    user: "root"
    network_mode: "host"
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
    volumes:
      - ${RULES_DIR}:/var/lib/suricata/rules
      - ${LOGS_DIR}:/var/log/suricata
      - ${SURICATA_YAML}:/etc/suricata/suricata.yaml
    command: suricata -c /etc/suricata/suricata.yaml -q 0
EOF
    echo "Docker Compose file created."
}

# 5. Set up iptables for IPS mode with a fail-safe
setup_iptables() {
    echo "Configuring iptables to redirect traffic to Suricata..."
    sudo iptables -I INPUT -i ${MONITORED_INTERFACE} -j NFQUEUE --queue-num 0 --queue-bypass
    sudo iptables -I OUTPUT -o ${MONITORED_INTERFACE} -j NFQUEUE --queue-num 0 --queue-bypass
    echo "iptables rules added for interface ${MONITORED_INTERFACE}."
    echo "IMPORTANT: These rules are NOT persistent and will be lost on reboot."
}

# --- Script Execution ---
main() {
    cleanup_previous_run
    check_dependencies
    select_interface
    setup_environment
    create_docker_compose
    
    echo "Pulling and starting Suricata container..."
    sudo docker-compose pull
    sudo docker-compose up -d
    
    echo "Waiting a few seconds for Suricata to initialize..."
    sleep 5
    
    setup_iptables
    
    echo "Success! Suricata is running in full IPS mode."
    echo "   Any traffic matching a signature will now be dropped."
    echo "   To verify, test with: curl http://testmynids.org/uid/index.html"
    echo "   The curl command should time out, proving traffic is being blocked."
    echo "   Check the Suricata action log with: sudo docker exec suricata tail -f /var/log/suricata/fast.log"
}

main