#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Wazuh Master Installation Script for Oracle Linux 9 (CORRECTED)
# Target Version: 4.14.1
#
# FIXED FOR ORACLE LINUX 9:
#   1. Added Seccomp bypass to prevent Filebeat crash (INVALIDARGUMENT).
#   2. Removed incompatible external module download (wazuh-filebeat-0.4).
#   3. Switched Filebeat config to direct JSON input for stability.

# --- Configuration Variables ---
WAZUH_MAJOR="4.14"
WAZUH_VERSION="4.14.1"
INSTALL_DIR="/root/wazuh-install-temp"
CURRENT_DIR=$(pwd)
WAZUH_PASSWORD="Changeme1!" # Set your desired password here
# -----------------------------

echo "--- [1/8] Cleaning any previous installations ---"
echo "Adjusting SELinux to Permissive for installation..."
setenforce 0 || true
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config

echo "Stopping services..."
systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager filebeat elasticsearch kibana 2>/dev/null || true

echo "Removing packages..."
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null || true

echo "Wiping config, data, and log directories..."
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat
rm -rf /var/lib/wazuh-indexer /var/lib/wazuh-manager /var/lib/wazuh-dashboard /var/lib/filebeat
rm -rf /usr/share/wazuh-indexer /usr/share/wazuh-manager /usr/share/wazuh-dashboard /usr/share/filebeat
rm -rf /var/log/wazuh-indexer /var/log/wazuh-manager /var/log/wazuh-dashboard /var/log/filebeat
rm -rf /var/ossec 

if [ -d "$INSTALL_DIR/wazuh-certificates" ]; then
    echo "Preserving existing certificates..."
else
    echo "Wiping temp directory..."
    rm -rf $INSTALL_DIR
    mkdir -p $INSTALL_DIR
fi

echo "Installing necessary tools..."
dnf install -y coreutils curl unzip wget libcap tar gnupg openssl

# --- [2/8] Repositories ---
echo "--- [2/8] Setting up Repositories ---"
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# --- [3/8] Certificates ---
echo "--- [3/8] Generating SSL Certificates ---"
cd $INSTALL_DIR

if [ -d "wazuh-certificates" ]; then
    echo "Certificates directory found. Skipping generation."
else
    echo "Generating new certificates..."
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/wazuh-certs-tool.sh
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/config.yml

    cat > config.yml <<EOF
nodes:
  indexer:
    - name: node-1
      ip: 127.0.0.1
  server:
    - name: wazuh-1
      ip: 127.0.0.1
  dashboard:
    - name: dashboard
      ip: 127.0.0.1
EOF
    bash wazuh-certs-tool.sh -A
fi

# --- [4/8] Wazuh Indexer (Database) ---
echo "--- [4/8] Installing Wazuh Indexer ---"
dnf install -y wazuh-indexer-$WAZUH_VERSION

# Deploy Certs
mkdir -p /etc/wazuh-indexer/certs
cp wazuh-certificates/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
cp wazuh-certificates/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem
cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Config
cat > /etc/wazuh-indexer/opensearch.yml <<EOF
network.host: 127.0.0.1
node.name: node-1
cluster.initial_master_nodes: ["node-1"]
plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US
plugins.security.nodes_dn:
  - CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US
compatibility.override_main_response_version: true
EOF

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

echo "Waiting for Indexer to initialize (Max 5 mins)..."
RETRIES=0
until curl -k -s https://127.0.0.1:9200 >/dev/null; do
    if [ $RETRIES -eq 30 ]; then
        echo "ERROR: Indexer failed to start."
        exit 1
    fi
    sleep 10
    ((RETRIES++))
    echo "Waiting... ($RETRIES/30)"
done

# Initialize Security
if [ -d "/usr/share/wazuh-indexer/jdk" ]; then
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
else
    # Fallback if specific JDK path varies
    export JAVA_HOME=$(ls -d /usr/share/wazuh-indexer/jdk* | head -n 1)
fi

/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -p 9200 \
  -icl \
  -h 127.0.0.1

echo "Changing admin password..."
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$WAZUH_PASSWORD" | tail -n 1 > /tmp/hash.txt
HASH=$(cat /tmp/hash.txt)
sed -i "0,/hash:.*/s|hash:.*|hash: \"$HASH\"|" /etc/wazuh-indexer/opensearch-security/internal_users.yml

/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -p 9200 \
  -icl \
  -h 127.0.0.1

# --- [5/8] Wazuh Manager & Filebeat ---
echo "--- [5/8] Installing Manager & Filebeat ---"
dnf install -y wazuh-manager-$WAZUH_VERSION filebeat

systemctl enable wazuh-manager
systemctl start wazuh-manager

echo "Setting Wazuh API credentials..."
sleep 10
/var/ossec/framework/python/bin/python3 <<EOF
import sys
try:
    from wazuh.security import update_user
    update_user(user_id="1", password="$WAZUH_PASSWORD")
    print("SUCCESS: Wazuh API password updated.")
except Exception as e:
    print(f"ERROR: Failed to update password: {e}")
    sys.exit(1)
EOF

/var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
/var/ossec/bin/wazuh-keystore -f indexer -k password -v "$WAZUH_PASSWORD"

sed -i "s|<host>https://0.0.0.0:9200</host>|<host>https://127.0.0.1:9200</host>|g" /var/ossec/etc/ossec.conf
if grep -q "<ssl_verification>" /var/ossec/etc/ossec.conf; then
    sed -i "s|<ssl_verification>yes</ssl_verification>|<ssl_verification>no</ssl_verification>|g" /var/ossec/etc/ossec.conf
else
    sed -i '/<ssl>/a \      <ssl_verification>no</ssl_verification>' /var/ossec/etc/ossec.conf
fi

systemctl restart wazuh-manager

# [CRITICAL FIX] Filebeat Seccomp Override for Oracle Linux 9
echo "Applying Filebeat Seccomp override (Fixes INVALIDARGUMENT crash)..."
mkdir -p /etc/systemd/system/filebeat.service.d
cat > /etc/systemd/system/filebeat.service.d/override.conf <<EOF
[Service]
SystemCallFilter=
EOF
systemctl daemon-reload

# [CRITICAL FIX] Simplified Filebeat Configuration (No broken modules)
echo "Applying Filebeat Configuration..."
cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.overwrite_keys: true
    json.add_error_key: true
    json.message_key: log

output.elasticsearch:
  hosts: ["127.0.0.1:9200"]
  protocol: https
  username: "admin"
  password: "$WAZUH_PASSWORD"
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.verification_mode: none

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.enabled: false
EOF

mkdir -p /etc/filebeat/certs
cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chmod 644 /etc/filebeat/filebeat.yml

# --- [6/8] Filebeat Template ---
echo "--- [6/8] Installing Filebeat Template ---"
curl -L --retry 5 --retry-delay 10 --connect-timeout 60 -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v$WAZUH_VERSION/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

# Initialize Index Pattern
echo "Initializing Filebeat..."
RETRIES=0
until filebeat setup --index-management \
  -E setup.template.json.enabled=true \
  -E setup.template.json.path=/etc/filebeat/wazuh-template.json \
  -E setup.template.json.name=wazuh \
  -E output.elasticsearch.username=admin \
  -E output.elasticsearch.password="$WAZUH_PASSWORD" \
  -E output.elasticsearch.ssl.verification_mode=none; do
  
    if [ $RETRIES -eq 10 ]; then
        echo "ERROR: Failed to run filebeat setup."
        exit 1
    fi
    echo "Filebeat setup failed. Retrying... ($RETRIES/10)"
    sleep 10
    ((RETRIES++))
done

systemctl enable filebeat
systemctl start filebeat

# --- [7/8] Wazuh Dashboard ---
echo "--- [7/8] Installing Wazuh Dashboard ---"
dnf install -y wazuh-dashboard-$WAZUH_VERSION

mkdir -p /etc/wazuh-dashboard/certs
cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

cat > /etc/wazuh-dashboard/opensearch_dashboards.yml <<EOF
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://127.0.0.1:9200
opensearch.ssl.verificationMode: none
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true
opensearch.username: admin
opensearch.password: $WAZUH_PASSWORD
EOF

mkdir -p /usr/share/wazuh-dashboard/data/wazuh/config
cat > /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml <<EOF
hosts:
  - default:
      url: https://127.0.0.1
      port: 55000
      username: wazuh
      password: $WAZUH_PASSWORD
      run_as: false
      allow_insecure_connection: true
EOF

chmod 600 /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

echo "--- INSTALLATION COMPLETE ---"
echo "Generating initial alerts to create index pattern..."
systemctl restart wazuh-manager

SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Access Dashboard at: https://$SERVER_IP"
echo "Username: admin"
echo "Password: $WAZUH_PASSWORD"