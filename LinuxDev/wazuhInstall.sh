#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Wazuh Manual Installation Script for Oracle Linux 9
# Optimized for Single-Node (All-in-One) with 1GB RAM Limit
# TARGET VERSION: 4.14.1

# --- Configuration Variables ---
WAZUH_MAJOR="4.14"       # Used for URLs
WAZUH_VERSION="4.14.1"   # Used for Package Pinning
INSTALL_DIR="/root/wazuh-install-temp"
mkdir -p $INSTALL_DIR

echo "--- [1/7] Cleaning up previous failed installations ---"
# Stop and remove potential conflicting services
systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager filebeat elasticsearch kibana 2>/dev/null || true
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null || true
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat /var/lib/wazuh-indexer

echo "--- [2/7] Setting up Repositories ---"
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

echo "--- [3/7] Generating SSL Certificates ---"
cd $INSTALL_DIR
# Download tools (Using 4.14 path as patch folders usually don't exist for these tools)
curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/$WAZUH_MAJOR/config.yml

# Create a single-node configuration (All on 127.0.0.1)
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
tar -cvf wazuh-certificates.tar -C wazuh-certificates/ .

echo "--- [4/7] Installing & Configuring Wazuh Indexer (Database) ---"
# Pinning version to 4.14.1
dnf install -y wazuh-indexer-$WAZUH_VERSION

# CRITICAL: Force 1GB RAM Limit
sed -i 's/-Xms4g/-Xms1g/' /etc/wazuh-indexer/jvm.options
sed -i 's/-Xmx4g/-Xmx1g/' /etc/wazuh-indexer/jvm.options

# Deploy Certs
mkdir -p /etc/wazuh-indexer/certs
tar -xf wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ node-1.pem node-1-key.pem admin.pem admin-key.pem root-ca.pem
mv /etc/wazuh-indexer/certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
mv /etc/wazuh-indexer/certs/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Config opensearch.yml for Single Node
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

# Initialize Security (This loads the certs into the DB)
echo "Initializing Indexer Security..."
# Wait loop to ensure service is up before running init
until curl -k -s https://127.0.0.1:9200 >/dev/null; do sleep 5; echo "Waiting for Indexer..."; done
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

echo "--- [5/7] Installing Wazuh Manager ---"
# Pinning version to 4.14.1
dnf install -y wazuh-manager-$WAZUH_VERSION

# Enable Vulnerability Detector
sed -i 's/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/' /var/ossec/etc/ossec.conf

systemctl enable wazuh-manager
systemctl start wazuh-manager

echo "--- [6/7] Installing & Configuring Filebeat ---"
dnf install -y filebeat

# Configure Filebeat (using 4.14 template)
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/$WAZUH_MAJOR/tpl/wazuh/filebeat/filebeat.yml
# Point Filebeat to local Indexer
sed -i 's/output.elasticsearch.hosts: \["127.0.0.1:9200"\]/output.elasticsearch.hosts: \["127.0.0.1:9200"\]\n  protocol: https\n  ssl.certificate_authorities: \["\/etc\/filebeat\/certs\/root-ca.pem"\]\n  ssl.certificate: "\/etc\/filebeat\/certs\/filebeat.pem"\n  ssl.key: "\/etc\/filebeat\/certs\/filebeat-key.pem"\n  ssl.verification_mode: none/' /etc/filebeat/filebeat.yml

# Deploy Certs to Filebeat
mkdir -p /etc/filebeat/certs
tar -xf wazuh-certificates.tar -C /etc/filebeat/certs/ wazuh-1.pem wazuh-1-key.pem root-ca.pem
mv /etc/filebeat/certs/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
mv /etc/filebeat/certs/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*

# Set default passwords
filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

systemctl enable filebeat
systemctl start filebeat

echo "--- [7/7] Installing Wazuh Dashboard ---"
# Pinning version to 4.14.1
dnf install -y wazuh-dashboard-$WAZUH_VERSION

# Deploy Certs to Dashboard
mkdir -p /etc/wazuh-dashboard/certs
tar -xf wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ dashboard.pem dashboard-key.pem root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Configure Dashboard SSL
cat >> /etc/wazuh-dashboard/opensearch_dashboards.yml <<EOF
server.ssl.enabled: true
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
opensearch.ssl.verificationMode: none
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
opensearch.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
opensearch.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
EOF

systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

echo "--- INSTALLATION COMPLETE ---"
echo "Access Dashboard at: https://<YOUR_SERVER_IP>"
echo "Username: admin"
echo "Password: admin"