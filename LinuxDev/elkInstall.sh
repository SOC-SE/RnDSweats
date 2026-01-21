#!/bin/bash

# Modified ELK Installer
# - Downloads from official Elastic repos
# - Sets password to 'Changeme1!'
# - Allows Kibana access from ANY IP
# - WAITS for ES to fully initialize before configuring

# Set colors for status messages
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting ELK Stack Installation...${NC}"

# Function for RHEL/CentOS/Oracle Linux
RHEL(){
    IS_RHEL=true
    # Switched to official Elastic download URLs
    ES="https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.13.2-x86_64.rpm"
    KB="https://artifacts.elastic.co/downloads/kibana/kibana-8.13.2-x86_64.rpm"
    FB="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.2-x86_64.rpm"
    
    echo -e "${GREEN}Downloading RPM packages...${NC}"
    curl -L -s -O $ES
    curl -L -s -O $KB
    curl -L -s -O $FB

    echo -e "${GREEN}Installing RPM packages...${NC}"
    rpm -i elasticsearch-8.13.2-x86_64.rpm 
    rpm -i kibana-8.13.2-x86_64.rpm 
    rpm -i filebeat-8.13.2-x86_64.rpm
}

# Function for Debian/Ubuntu
DEBIAN(){
    # Switched to official Elastic download URLs
    echo -e "${GREEN}Downloading DEB packages...${NC}"
    wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.13.2-amd64.deb
    wget -q https://artifacts.elastic.co/downloads/kibana/kibana-8.13.2-amd64.deb
    wget -q https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.2-amd64.deb
    
    echo -e "${GREEN}Installing DEB packages...${NC}"
    dpkg -i elasticsearch-8.13.2-amd64.deb kibana-8.13.2-amd64.deb filebeat-8.13.2-amd64.deb
}

UBUNTU(){
    DEBIAN
}

# OS Detection
if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $(cat /etc/os-release | grep -qi Ubuntu); then
        UBUNTU
    else
        DEBIAN
    fi
fi

TMP=$(mktemp)

echo -e "${GREEN}Configuring Services...${NC}"
systemctl daemon-reload
systemctl enable elasticsearch
systemctl enable kibana

# Start ES
systemctl start elasticsearch

# --- CRITICAL FIX: Wait for Elasticsearch to initialize ---
echo -e "${GREEN}Waiting for Elasticsearch to initialize (this may take a minute)...${NC}"
# Loop until curl returns HTTP 401 (Unauthorized), which means ES is UP and listening.
# -s = silent, -k = ignore SSL cert, -I = head request only
until curl -s -k -I https://127.0.0.1:9200 | grep -q "401 Unauthorized"; do
    echo "Elasticsearch is still starting up... (sleeping 5s)"
    sleep 5
done
echo -e "${GREEN}Elasticsearch is ready!${NC}"
# ----------------------------------------------------------

# Kibana Configuration
echo -e "${GREEN}Generating Kibana Enrollment Token...${NC}"

# Check if token generation works before proceeding
token=$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana)
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to generate enrollment token. Exiting."
    exit 1
fi

/usr/share/kibana/bin/kibana-encryption-keys generate | tail -4 >> /etc/kibana/kibana.yml
echo 'server.host: "0.0.0.0"' >> /etc/kibana/kibana.yml

# Apply token
/usr/share/kibana/bin/kibana-setup --enrollment-token=$token 

systemctl restart kibana

echo -e "${GREEN}Setting Credentials...${NC}"

# 1. Reset password to an auto-generated one (Batch mode -s -b)
TEMP_PASS=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b)

# 2. Use the temp password to set your custom password via API
curl -k -X POST -u "elastic:$TEMP_PASS" -H "Content-Type: application/json" \
"https://127.0.0.1:9200/_security/user/elastic/_password" \
-d '{"password" : "Changeme1!"}'

# Set PASS variable for the rest of the script
PASS="Changeme1!"

# Configure Filebeat with the new credentials
# Extract CA fingerprint
CA=$(openssl x509 -fingerprint -sha256 -noout -in /etc/elasticsearch/certs/http_ca.crt | awk -F '=' '{print $2}' | sed 's/://g')

sed -e 's/hosts: \["localhost:9200"\]/hosts: \["https:\/\/localhost:9200"\]/g; /hosts: \["https:\/\/localhost:9200"\]/a \ \n  username: "elastic"\n  password: "'"$PASS"'"\n  ssl:\n    enabled: true\n    ca_trusted_fingerprint: "'"$CA"'"' /etc/filebeat/filebeat.yml > $TMP
mv $TMP /etc/filebeat/filebeat.yml

# Run Filebeat Setup
echo -e "${GREEN}Setting up Filebeat...${NC}"
filebeat setup --index-management -E output.logstash.enabled=false  -E "output.elasticsearch.ssl.enabled=true" -E "output.elasticsearch.ssl.ca_trusted_fingerprint=$CA" -E 'output.elasticsearch.hosts=["https://127.0.0.1:9200"]'

# Append optional config (commented out by default)
cat << EOF >> /etc/filebeat/filebeat.yml

# ----- Example filestream config -----
#filebeat.inputs:
#  - type: filestream
#    id: remote
#    enabled: true
#    paths:
#      - /var/log/remote/*/*.log

EOF

echo -e "${GREEN}Installation Complete!${NC}"
echo "Kibana is available at port 5601."
echo "Username: elastic"
echo "Password: Changeme1!"