#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Wazuh Master Installation Script for Oracle Linux 9
# Target Version: 4.14.1
# Fixes: 
#   - Prevents duplicate certificate generation error
#   - Forces IPv4 (127.0.0.1) for internal backend communication
#   - Fixes missing Filebeat module
#   - Handles SELinux for Oracle Linux
#   - Robust Filebeat configuration (avoids sed)
#   - Added timeout for Indexer startup
#   - Fixes Dashboard "Not Ready" by matching curl behavior (Basic Auth only)
#   - Fixes internal_users.yml corruption (only changes admin pass)

# --- Configuration Variables ---
WAZUH_MAJOR="4.14"
WAZUH_VERSION="4.14.1"
INSTALL_DIR="/root/wazuh-install-temp"
CURRENT_DIR=$(pwd)

# --- CUSTOMIZABLE VARIABLES ---
WAZUH_PASSWORD="Changeme1!" # Set your desired password here
# -----------------------------

echo "--- [1/8] Deep Cleaning previous installations ---"
# Adjust SELinux for Oracle Linux 9 (Permissive is safer for initial install)
echo "Adjusting SELinux to Permissive for installation..."
setenforce 0 || true
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config

systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager filebeat elasticsearch kibana 2>/dev/null || true
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null || true

echo "Removing config, data, and log directories..."
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat
rm -rf /var/lib/wazuh-indexer /var/lib/wazuh-manager /var/lib/wazuh-dashboard /var/lib/filebeat
rm -rf /usr/share/wazuh-indexer /usr/share/wazuh-manager /usr/share/wazuh-dashboard /usr/share/filebeat
rm -rf /var/log/wazuh-indexer /var/log/wazuh-manager /var/log/wazuh-dashboard /var/log/filebeat

# Only wipe temp dir if certs don't exist to save time
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

# Improved Check: If directory exists, skip generation to avoid error
if [ -d "wazuh-certificates" ]; then
    echo "Certificates directory found. Skipping generation."
else
    echo "Generating new certificates..."
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/wazuh-certs-tool.sh
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/config.yml

    # Force 127.0.0.1 for all internal components
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

# Final verification
if [ ! -f "wazuh-certificates/node-1.pem" ]; then
    echo "ERROR: Certificates were not generated correctly."
    exit 1
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

# Config (Strictly 127.0.0.1)
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
EOF

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

echo "Waiting for Indexer to initialize (Max 5 mins)..."
RETRIES=0
until curl -k -s https://127.0.0.1:9200 >/dev/null; do
    if [ $RETRIES -eq 30 ]; then
        echo "ERROR: Indexer failed to start within 5 minutes. Check /var/log/wazuh-indexer/wazuh-cluster.log"
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
    echo "ERROR: Java Home not found at /usr/share/wazuh-indexer/jdk/. Indexer layout may have changed."
    exit 1
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

# Change default admin password
echo "Changing admin password..."
# Capture ONLY the hash (ignoring tool banners)
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$WAZUH_PASSWORD" | tail -n 1 > /tmp/hash.txt
HASH=$(cat /tmp/hash.txt)

# Use refined sed to ONLY replace the FIRST occurrence of 'hash:' (which is the admin user)
# This prevents breaking other system users like kibanaserver
sed -i "0,/hash:.*/s//hash: \"$HASH\"/" /etc/wazuh-indexer/opensearch-security/internal_users.yml

# Re-run securityadmin to apply password change
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

# Start Manager
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Configure Filebeat (Retry Logic)
curl -L --retry 5 --retry-delay 10 --connect-timeout 60 -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/$WAZUH_MAJOR/tpl/wazuh/filebeat/filebeat.yml

# Config Overwrite (Replacing fragile sed)
echo "Applying Filebeat Configuration..."
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak
cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.enabled: false

output.elasticsearch:
  hosts: ["127.0.0.1:9200"]
  protocol: https
  username: "admin"
  password: "$WAZUH_PASSWORD"
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"
  ssl.verification_mode: none
EOF

mkdir -p /etc/filebeat/certs
cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*

filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo "$WAZUH_PASSWORD" | filebeat keystore add password --stdin --force

# --- [6/8] Filebeat Module & Template ---
echo "--- [6/8] Installing Filebeat Module & Template ---"

# 1. Handle the Template (Use local file if present)
if [ -f "$CURRENT_DIR/wazuh-template.json" ]; then
    echo "Found local wazuh-template.json. Using it."
    cp "$CURRENT_DIR/wazuh-template.json" /etc/filebeat/wazuh-template.json
else
    echo "Local wazuh-template.json not found. Attempting download..."
    curl -L --retry 5 --retry-delay 10 --connect-timeout 60 -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v$WAZUH_VERSION/extensions/elasticsearch/7.x/wazuh-template.json
fi
chmod go+r /etc/filebeat/wazuh-template.json

# 2. Handle the Module (Download with retry)
echo "Downloading Wazuh Filebeat Module..."
curl -L --retry 5 --retry-delay 10 --connect-timeout 60 -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

# 3. Initialize Index Pattern
echo "Initializing Filebeat..."
filebeat setup --index-management \
  -E setup.template.json.enabled=true \
  -E setup.template.json.path=/etc/filebeat/wazuh-template.json \
  -E setup.template.json.name=wazuh \
  -E setup.ilm.overwrite=true \
  -E setup.ilm.enabled=false \
  -E output.elasticsearch.hosts=["127.0.0.1:9200"] \
  -E output.elasticsearch.protocol=https \
  -E output.elasticsearch.username=admin \
  -E output.elasticsearch.password="$WAZUH_PASSWORD" \
  -E output.elasticsearch.ssl.certificate_authorities=["/etc/filebeat/certs/root-ca.pem"] \
  -E output.elasticsearch.ssl.certificate="/etc/filebeat/certs/filebeat.pem" \
  -E output.elasticsearch.ssl.key="/etc/filebeat/certs/filebeat-key.pem" \
  -E output.elasticsearch.ssl.verification_mode=none

systemctl enable filebeat
systemctl start filebeat

# --- [7/8] Wazuh Dashboard ---
echo "--- [7/8] Installing Wazuh Dashboard ---"
dnf install -y wazuh-dashboard-$WAZUH_VERSION

# Deploy Certs
mkdir -p /etc/wazuh-dashboard/certs
cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Configure Dashboard
# NOTE: We disable backend client auth (server.ssl.key/cert) to match the behavior of the working curl command.
# We only keep server.ssl.* (browser <-> dashboard) and ssl.certificateAuthorities (trusting the indexer CA).
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
opensearch.compatibility.override_main_response_version: true
EOF

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

echo "--- INSTALLATION COMPLETE ---"
# Grab IP for display only
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Access Dashboard at: https://$SERVER_IP"
echo "Username: admin"
echo "Password: $WAZUH_PASSWORD"