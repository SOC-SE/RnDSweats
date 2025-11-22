#!/bin/bash

# Modified ELK Installer
# - Downloads from official Elastic repos
# - Sets password to 'Changeme1!'
# - Allows Kibana access from ANY IP

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
    
    # Stop firewalld to allow iptables management or direct access
    systemctl stop firewalld
    systemctl disable firewalld
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

systemctl start elasticsearch

# Firewall Configuration - Modified to allow ALL traffic on 5601
# Removed "-s" source restriction
iptables -A INPUT -p tcp --dport 5601 -j ACCEPT

# Kibana Configuration
/usr/share/kibana/bin/kibana-encryption-keys generate | tail -4 >> /etc/kibana/kibana.yml
echo 'server.host: "0.0.0.0"' >> /etc/kibana/kibana.yml
token=$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana)
/usr/share/kibana/bin/kibana-setup --enrollment-token=$token 

systemctl restart kibana

echo -e "${GREEN}Setting Credentials...${NC}"

# Manually set the password to Changeme1!
# We use the -i (interactive) flag and pipe the password to stdin twice (for confirmation)
echo "Changeme1!
Changeme1!" | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i

# Configure Filebeat with the new credentials
CA=$(openssl x509 -fingerprint -sha256 -noout -in /etc/elasticsearch/certs/http_ca.crt | awk -F '=' '{print $2}' | sed 's/://g')

# Set the PASS variable for the sed command below
PASS="Changeme1!"

sed -e 's/hosts: \["localhost:9200"\]/hosts: \["https:\/\/localhost:9200"\]/g; /hosts: \["https:\/\/localhost:9200"\]/a \ \n  username: "elastic"\n  password: "'"$PASS"'"\n  ssl:\n    enabled: true\n    ca_trusted_fingerprint: "'"$CA"'"' /etc/filebeat/filebeat.yml > $TMP
mv $TMP /etc/filebeat/filebeat.yml

# Run Filebeat Setup
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