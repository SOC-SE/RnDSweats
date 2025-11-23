#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Wazuh Manual Installation Script for Oracle Linux 9
# Optimized for Single-Node (All-in-One) with 1GB RAM Limit
# TARGET VERSION: 4.14.1

# --- Configuration Variables ---
WAZUH_MAJOR="4.14"       # Used for URLs
WAZUH_VERSION="4.14.1"   # Used for Package Pinning
INSTALL_DIR="/root/wazuh-install-temp"

# --- [1/7] Preparation & Cleanup ---
echo "--- [1/7] Deep Cleaning previous installations ---"
systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager filebeat elasticsearch kibana 2>/dev/null || true
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null || true

echo "Removing config, data, and log directories..."
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat
rm -rf /var/lib/wazuh-indexer /var/lib/wazuh-manager /var/lib/wazuh-dashboard /var/lib/filebeat
rm -rf /usr/share/wazuh-indexer /usr/share/wazuh-manager /usr/share/wazuh-dashboard /usr/share/filebeat
rm -rf /var/log/wazuh-indexer /var/log/wazuh-manager /var/log/wazuh-dashboard /var/log/filebeat

echo "Wiping temporary install directory..."
rm -rf $INSTALL_DIR
mkdir -p $INSTALL_DIR

echo "Installing necessary tools..."
dnf install -y coreutils curl unzip wget libcap tar gnupg openssl

# --- [2/7] Repositories ---
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

# --- [3/7] Certificates ---
echo "--- [3/7] Generating SSL Certificates ---"
cd $INSTALL_DIR
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

# DEBUG: List generated certs to ensure they exist
echo "Verifying certificates..."
if [ ! -f "wazuh-certificates/node-1.pem" ]; then
    echo "ERROR: Certificates were not generated correctly. Listing contents of wazuh-certificates:"
    ls -R wazuh-certificates/
    exit 1
fi
echo "Certificates generated successfully."

# --- [4/7] Wazuh Indexer ---
echo "--- [4/7] Installing & Configuring Wazuh Indexer ---"
dnf install -y wazuh-indexer-$WAZUH_VERSION

# CRITICAL: Force 1GB RAM Limit
sed -i 's/-Xms4g/-Xms1g/' /etc/wazuh-indexer/jvm.options
sed -i 's/-Xmx4g/-Xmx1g/' /etc/wazuh-indexer/jvm.options

# Deploy Certs (Direct Copy instead of tar)
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
EOF

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

echo "Waiting for Indexer to initialize (approx 30s)..."
# Loop until port 9200 is listening, even if it returns 503 or 401
count=0
while ! curl -k -s https://127.0.0.1:9200 >/dev/null; do
    echo "Waiting for Indexer port 9200... ($count/30)"
    sleep 5
    count=$((count+1))
    if [ $count -ge 30 ]; then
        echo "Indexer failed to start. Checking logs..."
        tail -n 20 /var/log/wazuh-indexer/wazuh-cluster.log
        exit 1
    fi
done

echo "Initializing Indexer Security (Explicit Method)..."
# Using the explicit securityadmin.sh command instead of the helper script
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

# --- [5/7] Wazuh Manager ---
echo "--- [5/7] Installing Wazuh Manager ---"
dnf install -y wazuh-manager-$WAZUH_VERSION

# Enable Vulnerability Detector
sed -i 's/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/' /var/ossec/etc/ossec.conf

systemctl enable wazuh-manager
systemctl start wazuh-manager

# --- [6/7] Filebeat ---
echo "--- [6/7] Installing & Configuring Filebeat ---"
dnf install -y filebeat

# Configure Filebeat
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/$WAZUH_MAJOR/tpl/wazuh/filebeat/filebeat.yml
sed -i 's/output.elasticsearch.hosts: \["127.0.0.1:9200"\]/output.elasticsearch.hosts: \["127.0.0.1:9200"\]\n  protocol: https\n  ssl.certificate_authorities: \["\/etc\/filebeat\/certs\/root-ca.pem"\]\n  ssl.certificate: "\/etc\/filebeat\/certs\/filebeat.pem"\n  ssl.key: "\/etc\/filebeat\/certs\/filebeat-key.pem"\n  ssl.verification_mode: none/' /etc/filebeat/filebeat.yml

# Deploy Certs (Direct Copy)
mkdir -p /etc/filebeat/certs
cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem

chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*

# Default passwords
filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

systemctl enable filebeat
systemctl start filebeat

# --- [7/7] Dashboard ---
echo "--- [7/7] Installing Wazuh Dashboard ---"
dnf install -y wazuh-dashboard-$WAZUH_VERSION

# Deploy Certs (Direct Copy)
mkdir -p /etc/wazuh-dashboard/certs
cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem

chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Config Dashboard
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