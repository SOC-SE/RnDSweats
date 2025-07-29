#!/bin/bash
set -euo pipefail

# Define variables
WAZUH_MANAGER_IP="172.20.241.20"
GATEWAY_IP="172.20.242.10"

# Detect distro for package manager
if [ -f /etc/debian_version ]; then  # Debian 10
    PKG_MGR="apt-get"
    INSTALL_CMD="install -y"
    UPDATE_CMD="update -y"
    KEY_CMD="apt-key add -"
    REPO_FILE="/etc/apt/sources.list.d/wazuh.list"
    REPO_LINE="deb https://packages.wazuh.com/4.x/apt/ stable main"
elif [ -f /etc/redhat-release ]; then  # CentOS 7 or Fedora 21
    PKG_MGR="yum"
    INSTALL_CMD="install -y"
    UPDATE_CMD="update -y"
    KEY_CMD="rpm --import -"
    REPO_FILE="/etc/yum.repos.d/wazuh.repo"
    REPO_LINE=$(curl -s https://packages.wazuh.com/4.x/yum/wazuh.repo)
else
    echo "Unsupported distro" && exit 1
fi

# Install Wazuh Agent (idempotent)
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | $KEY_CMD
    echo "$REPO_LINE" | tee $REPO_FILE > /dev/null
    $PKG_MGR $UPDATE_CMD
    $PKG_MGR $INSTALL_CMD wazuh-agent
fi
sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/g" /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start

# Change default gateway and persist (idempotent: overwrite config)
ip route del default || true
ip route add default via $GATEWAY_IP
if [ -f /etc/debian_version ]; then
    echo "up ip route add default via $GATEWAY_IP" | tee -a /etc/network/interfaces > /dev/null
elif [ -f /etc/redhat-release ]; then
    IFACE=$(nmcli -t -f NAME c show --active | head -1) || IFACE="eth0"
    nmcli con mod "$IFACE" ipv4.gateway $GATEWAY_IP || sed -i "s/GATEWAY=.*/GATEWAY=$GATEWAY_IP/g" /etc/sysconfig/network
fi
systemctl restart networking || systemctl restart NetworkManager
