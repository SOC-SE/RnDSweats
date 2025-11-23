#!/bin/bash

# Wazuh Manual Installation Script for Oracle Linux 9 / RHEL 9
# optimized for "Lightweight" Single-Node Deployment (1GB RAM limit)

# 1. SETUP & CLEANUP
echo "--- [1/6] Cleaning up and setting up repositories ---"
systemctl stop wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null
dnf remove -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat elasticsearch kibana 2>/dev/null
rm -rf /etc/wazuh-indexer /etc/wazuh-manager /etc/wazuh-dashboard /etc/filebeat /var/lib/wazuh-indexer

# Import GPG Key and Add Repo
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' > /etc/yum.repos.d/wazuh.repo

# 2. INSTALL CERTIFICATE TOOLS
echo "--- [2/6] Generating SSL Certificates ---"
dnf install -y curl tar unzip
mkdir -p /root/wazuh-certs
cd /root/wazuh-certs

# Download cert tool
curl -sO https://packages.wazuh.com/4.7/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Create config for Single Node (127.0.0.1)
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

# Generate Certs
bash wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .

# 3. INSTALL & CONFIGURE INDEXER (Database)
echo "--- [3/6] Installing Wazuh Indexer ---"
dnf install -y wazuh-indexer

# Apply Lightweight RAM Config (1GB Limit)
sed -i 's/-Xms4g/-Xms1g/' /etc/wazuh-indexer/jvm.options
sed -i 's/-Xmx4g/-Xmx1g/' /etc/wazuh-indexer/jvm.options

# Deploy Certs to Indexer
mkdir -p /etc/wazuh-indexer/certs
tar -xf /root/wazuh-certs/wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ node-1.pem node-1-key.pem admin.pem admin-key.pem root-ca.pem
mv /etc/wazuh-indexer/certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
mv /etc/wazuh-indexer/certs/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Config Indexer (Single Node)
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

# WAIT for Indexer to start
echo "Waiting for Indexer to initialize (approx 30s)..."
sleep 30

# Initialize Security
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

# 4. INSTALL & CONFIGURE MANAGER
echo "--- [4/6] Installing Wazuh Manager ---"
dnf install -y wazuh-manager

# Enable Vulnerability Detector & Disable Noisy Modules
sed -i 's/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/' /var/ossec/etc/ossec.conf # Enable Vuln
sed -i '/<wodle name="cis-cat">/,/<\/wodle>/s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/' /var/ossec/etc/ossec.conf

systemctl enable wazuh-manager
systemctl start wazuh-manager

# 5. INSTALL & CONFIGURE FILEBEAT (Log Shipper)
echo "--- [5/6] Installing Filebeat ---"
dnf install -y filebeat

# Deploy Certs to Filebeat
mkdir -p /etc/filebeat/certs
tar -xf /root/wazuh-certs/wazuh-certificates.tar -C /etc/filebeat/certs/ wazuh-1.pem wazuh-1-key.pem root-ca.pem
mv /etc/filebeat/certs/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
mv /etc/filebeat/certs/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*

# Configure Filebeat
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.7/tpl/wazuh/filebeat/filebeat.yml
sed -i 's/output.elasticsearch.hosts: \["127.0.0.1:9200"\]/output.elasticsearch.hosts: \["127.0.0.1:9200"\]\n  protocol: https\n  ssl.certificate_authorities: \["\/etc\/filebeat\/certs\/root-ca.pem"\]\n  ssl.certificate: "\/etc\/filebeat\/certs\/filebeat.pem"\n  ssl.key: "\/etc\/filebeat\/certs\/filebeat-key.pem"\n  ssl.verification_mode: none/' /etc/filebeat/filebeat.yml

# Set Default Password (admin:admin) in Filebeat Keystore
filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

systemctl enable filebeat
systemctl start filebeat

# 6. INSTALL & CONFIGURE DASHBOARD
echo "--- [6/6] Installing Wazuh Dashboard ---"
dnf install -y wazuh-dashboard

# Deploy Certs to Dashboard
mkdir -p /etc/wazuh-dashboard/certs
tar -xf /root/wazuh-certs/wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ dashboard.pem dashboard-key.pem root-ca.pem
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
echo "Access the dashboard at: https://<YOUR_SERVER_IP>"
echo "Username: admin"
echo "Password: admin"
echo "Note: Please change the default password immediately."