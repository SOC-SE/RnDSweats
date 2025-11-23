#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Wazuh FRESH Installation Script for Oracle Linux 9
# Goal: Establish a working baseline with zero custom tuning.
# Target Version: 4.14.1

# --- Configuration Variables ---
WAZUH_MAJOR="4.14"
WAZUH_VERSION="4.14.1"
INSTALL_DIR="/root/wazuh-install-temp"

echo "--- [1/6] Deep Cleaning previous installations ---"
# 1. Stop all services
systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager filebeat elasticsearch kibana 2>/dev/null || true

# 2. Remove packages
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null || true

# 3. Remove ALL configuration, data, and log directories
echo "Removing config, data, and log directories..."
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat
rm -rf /var/lib/wazuh-indexer /var/lib/wazuh-manager /var/lib/wazuh-dashboard /var/lib/filebeat
rm -rf /usr/share/wazuh-indexer /usr/share/wazuh-manager /usr/share/wazuh-dashboard /usr/share/filebeat
rm -rf /var/log/wazuh-indexer /var/log/wazuh-manager /var/log/wazuh-dashboard /var/log/filebeat

# 4. Wipe temp directory (Except certs if they exist, to save time)
if [ -d "$INSTALL_DIR/wazuh-certificates" ]; then
    echo "Preserving existing certificates..."
else
    echo "Wiping temp directory..."
    rm -rf $INSTALL_DIR
    mkdir -p $INSTALL_DIR
fi

echo "Installing necessary tools..."
dnf install -y coreutils curl unzip wget libcap tar gnupg openssl

# --- [2/6] Repositories ---
echo "--- [2/6] Setting up Repositories ---"
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

# --- [3/6] Certificates ---
echo "--- [3/6] Generating SSL Certificates ---"
cd $INSTALL_DIR

# Only generate if they don't exist
if [ ! -f "wazuh-certificates/node-1.pem" ]; then
    echo "Generating new certificates..."
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/wazuh-certs-tool.sh
    curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/config.yml

    # Define the node as 127.0.0.1 for all components
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
else
    echo "Certificates found. Skipping generation."
fi

# --- [4/6] Wazuh Indexer (Database) ---
echo "--- [4/6] Installing Wazuh Indexer ---"
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

# Minimal Config
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

echo "Waiting for Indexer to initialize..."
until curl -k -s https://127.0.0.1:9200 >/dev/null; do sleep 5; echo "Waiting..."; done

# Initialize Security
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -p 9200 \
  -icl \
  -h 127.0.0.1

# --- [5/6] Wazuh Manager & Filebeat ---
echo "--- [5/6] Installing Manager & Filebeat ---"
dnf install -y wazuh-manager-$WAZUH_VERSION filebeat

# Start Manager (Default Config)
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Configure Filebeat
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/$WAZUH_MAJOR/tpl/wazuh/filebeat/filebeat.yml
# FIX: Explicitly set 127.0.0.1
sed -i 's/output.elasticsearch.hosts: \["127.0.0.1:9200"\]/output.elasticsearch.hosts: \["127.0.0.1:9200"\]\n  protocol: https\n  ssl.certificate_authorities: \["\/etc\/filebeat\/certs\/root-ca.pem"\]\n  ssl.certificate: "\/etc\/filebeat\/certs\/filebeat.pem"\n  ssl.key: "\/etc\/filebeat\/certs\/filebeat-key.pem"\n  ssl.verification_mode: none/' /etc/filebeat/filebeat.yml

mkdir -p /etc/filebeat/certs
cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*

filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

systemctl enable filebeat
systemctl start filebeat

# --- [6/6] Wazuh Dashboard ---
echo "--- [6/6] Installing Wazuh Dashboard ---"
dnf install -y wazuh-dashboard-$WAZUH_VERSION

# Deploy Certs
mkdir -p /etc/wazuh-dashboard/certs
cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Configure Dashboard (OVERWRITE to ensure clean config)
# FIX: Force IPv4 127.0.0.1 instead of "localhost" to prevent IPv6 lookup errors
cat > /etc/wazuh-dashboard/opensearch_dashboards.yml <<EOF
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://127.0.0.1:9200
opensearch.ssl.verificationMode: certificate
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
opensearch.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
opensearch.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: true
EOF

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

echo "--- INSTALLATION COMPLETE ---"
echo "Access Dashboard at: https://<YOUR_SERVER_IP>"
echo "Username: admin"
echo "Password: admin"