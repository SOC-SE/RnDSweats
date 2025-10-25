#!/bin/bash

# Exit immediately if a command exits with a non-zero status or on pipe failures.
set -eo pipefail

# --- Script Configuration ---
CONFIG_ROOT="/etc/suricata"
LOGS_ROOT="/var/log/suricata"

DOCKER_COMPOSE_FILE="docker-compose.yml" # This file is temporary and stays local
CONFIG_DIR="${CONFIG_ROOT}"
RULES_DIR="${CONFIG_ROOT}/rules"
LOGS_DIR="${LOGS_ROOT}"
SURICATA_YAML="${CONFIG_DIR}/suricata.yaml"

# --- Main Functions ---

#Check if Splunk Forwarder is installed.
#There are some specific commands in here for the Splunk forwarder, so it should be installed first (if used in a comp with Splunk)
check_splunk_forwarder() {
    echo "Checking for SplunkForwarder service..."
    if ! systemctl status SplunkForwarder &> /dev/null; then
        echo "Warning: The 'SplunkForwarder' service was not found."
        echo "   This script is intended to be after the Splunk Universal Forwarder is installed."
        echo "   There are Splunk-specific fixes for setfacl file permissions on the suricata logs."
        echo "   These will need to be performed manually for Splunk if you wish to force the installation now."
        
        while true; do
            read -p "Do you want to continue with the Suricata installation anyway? (y/n): " yn
            case $yn in
                [Yy]* ) echo "Continuing installation..."; break;;
                [Nn]* ) echo "Exiting script."; exit 0;;
                * ) echo "Please answer yes (y) or no (n).";;
            esac
        done
    else
        echo "Found 'SplunkForwarder' service."
    fi
}

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
# UPDATED: This function now installs missing dependencies
check_dependencies() {
    echo "Checking for Docker and Docker Compose..."
    PKG_MANAGER=""
    
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    fi

    if [ -z "$PKG_MANAGER" ] && (! command -v docker &> /dev/null); then
        echo "Unsupported package manager. Please install Docker and Docker Compose manually."
        exit 1
    fi

    # 1. Check/Install Docker
    if ! command -v docker &> /dev/null; then
        echo "   Docker not found. Installing..."
        # Use the official convenience script for a reliable, distro-agnostic install
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        rm get-docker.sh
        # Add current user to docker group (good practice)
        sudo usermod -aG docker $USER || echo "   Could not add user to docker group. This is fine for this script."
        echo "   Docker installed."
    else
        echo "   Docker is already installed."
    fi

    # 2. Check/Install Docker Compose (v1, as used in the script)
    if ! command -v docker-compose &> /dev/null; then
        echo "   Docker Compose (v1) not found. Installing..."
        if [ "$PKG_MANAGER" == "apt" ]; then
            sudo apt update
            sudo apt install -y docker-compose
        elif [ "$PKG_MANAGER" == "dnf" ]; then
            sudo dnf install -y docker-compose
        elif [ "$PKG_MANAGER" == "yum" ]; then
            sudo yum install -y epel-release # docker-compose is in EPEL for CentOS/RHEL 7
            sudo yum install -y docker-compose
        else
            # Fallback to binary download if PKG_MANAGER was unknown but docker was found
            echo "   Package manager unknown. Attempting binary download for Docker Compose..."
            LATEST_COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
            if [ -z "$LATEST_COMPOSE_VER" ]; then
                echo "   Warning: Could not get latest docker-compose version. Using fallback 1.29.2."
                LATEST_COMPOSE_VER="1.29.2"
            fi
            sudo curl -L "https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VER}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            sudo chmod +x /usr/local/bin/docker-compose
        fi
        echo "   Docker Compose installed."
    else
        echo "   Docker Compose is already installed."
    fi
    
    # 3. Start Docker service
    if ! sudo systemctl is-active --quiet docker; then
        echo "   Starting Docker service..."
        sudo systemctl start docker
    fi
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
    sudo mkdir -p "${CONFIG_DIR}" "${RULES_DIR}" "${LOGS_DIR}"

    echo "Generating the default suricata.yaml configuration file..."
    sudo docker run --rm jasonish/suricata:latest cat /etc/suricata/suricata.yaml | sudo tee "${SURICATA_YAML}" > /dev/null

    echo "Modifying suricata.yaml for IPS mode and network settings..."
    sudo sed -i "/af-packet:/,/threads: auto/ s/#   - interface: default/  - interface: ${MONITORED_INTERFACE}/" "${SURICATA_YAML}"
    sudo sed -i 's/checksum-validation: yes/checksum-validation: no/' "${SURICATA_YAML}"
    sudo sed -i 's/#nfq:/nfq:/' "${SURICATA_YAML}"

    echo "Downloading and processing rulesets with suricata-update..."
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
    check_splunk_forwarder # NEW
    cleanup_previous_run
    check_dependencies # UPDATED
    select_interface
    setup_environment
    create_docker_compose
    
    echo "Pulling and starting Suricata container..."
    sudo docker-compose pull
    sudo docker-compose up -d
    
    echo "Waiting a few seconds for Suricata to initialize..."
    sleep 5
    
    setup_iptables
    
    #Necessary to give Splunk the perms to read the files, without changing all of the file perms
    #Yay for ACLs!!
    echo "Allowing Splunk user to read the log files..."
    sudo setfacl -R -m u:splunk:rX /var/log/suricata
    sudo setfacl -d -m u:splunk:rX /var/log/suricata
    
    echo "Success! Suricata is running in full IPS mode."
    echo "   Any traffic matching a signature will now be dropped."
    echo "   To verify, test with: curl http://testmynids.org/uid/index.html"
    echo "   The curl command should time out, proving traffic is being blocked."
    echo "   Check the Suricata action log with: sudo docker exec suricata tail -f /var/log/suricata/fast.log"
}

main