#!/bin/bash
# setup_linux_client.sh
# Configures Linux servers (CentOS 7, Fedora 21, Debian 10) to install Wazuh Agent, point to manager, and change default gateway.
# Assumes running as root. Detects distro and handles accordingly. Prioritizes speed and uptime.

set -e  # Exit on error
set -u  # Treat unset variables as error

# Variables
WAZUH_MANAGER_IP="172.20.241.20"
NEW_GATEWAY_IP="172.20.242.10"

# Step 1: Detect distribution and version
if [ -f /etc/redhat-release ]; then
    DISTRO="rpm"  # CentOS or Fedora (yum-based)
    if grep -q "Fedora" /etc/redhat-release; then
        FEDORA_VERSION=$(awk '{print $3}' /etc/fedora-release)
        if [ "$FEDORA_VERSION" -lt 22 ]; then
            echo "Warning: Fedora version $FEDORA_VERSION is not supported by Wazuh (requires 22+). Skipping Wazuh installation, but proceeding with gateway change."
            SKIP_WAZUH=true
        else
            SKIP_WAZUH=false
        fi
    else
        SKIP_WAZUH=false
    fi
elif [ -f /etc/debian_version ]; then
    DISTRO="deb"  # Debian
    SKIP_WAZUH=false
else
    echo "Unsupported distribution. Exiting."
    exit 1
fi

# Step 2: Update system
if [ "$DISTRO" == "rpm" ]; then
    yum update -y
elif [ "$DISTRO" == "deb" ]; then
    apt update -y
fi

# Step 3: Add Wazuh repository and install agent (if not skipped)
if [ "${SKIP_WAZUH:-false}" != "true" ]; then
    if [ "$DISTRO" == "rpm" ]; then
        if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
            cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        fi
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        yum install -y wazuh-agent
    elif [ "$DISTRO" == "deb" ]; then
        if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
            chmod 644 /usr/share/keyrings/wazuh.gpg
        fi
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        apt update -y
        apt install -y wazuh-agent
    fi

    # Step 4: Configure Wazuh agent to point to manager
    sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/g" /var/ossec/etc/ossec.conf

    # Step 5: Enable and start Wazuh agent service
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
fi

# Step 6: Change default gateway (temporary and persistent)
# Temporary change
ip route del default || true  # Remove existing if any
ip route add default via ${NEW_GATEWAY_IP}

# Persistent change based on distro
if [ "$DISTRO" == "rpm" ]; then
    # For CentOS/Fedora: Edit /etc/sysconfig/network
    if ! grep -q "^GATEWAY=${NEW_GATEWAY_IP}" /etc/sysconfig/network; then
        echo "GATEWAY=${NEW_GATEWAY_IP}" >> /etc/sysconfig/network
    fi
    systemctl restart NetworkManager || systemctl restart network
elif [ "$DISTRO" == "deb" ]; then
    # For Debian: Edit /etc/network/interfaces (assume primary iface is eth0; adjust if needed)
    IFACE=$(ip route | grep default | awk '{print $5}' || echo "eth0")
    if ! grep -q "^gateway ${NEW_GATEWAY_IP}" /etc/network/interfaces; then
        sed -i "/iface ${IFACE} inet static/a gateway ${NEW_GATEWAY_IP}" /etc/network/interfaces || echo "gateway ${NEW_GATEWAY_IP}" >> /etc/network/interfaces
    fi
    /etc/init.d/networking restart || systemctl restart networking
fi

# Step 7: Basic verification
if [ "${SKIP_WAZUH:-false}" != "true" ] && systemctl is-active --quiet wazuh-agent; then
    echo "Wazuh Agent installed, configured, and started successfully."
elif [ "${SKIP_WAZUH:-false}" == "true" ]; then
    echo "Wazuh installation skipped due to unsupported OS version."
else
    echo "Error: Wazuh Agent service failed to start."
    exit 1
fi

ip route show | grep default && echo "Default gateway updated successfully."
