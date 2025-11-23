#!/bin/bash
set -e

# Fix for "No template found for the selected index-pattern"
# Target Version: 4.14.1

echo "--- [1/3] Downloading missing Wazuh Template ---"
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

echo "--- [2/3] Downloading Wazuh Filebeat Module ---"
# This module tells Filebeat how to interpret Wazuh logs
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

echo "--- [3/3] Initializing Filebeat Setup ---"
# This command manually talks to the Indexer to create the Index Pattern
filebeat setup --index-management \
  -E setup.template.json.enabled=true \
  -E setup.template.json.path=/etc/filebeat/wazuh-template.json \
  -E setup.template.json.name=wazuh \
  -E setup.ilm.overwrite=true \
  -E setup.ilm.enabled=false \
  -E output.elasticsearch.hosts=["127.0.0.1:9200"] \
  -E output.elasticsearch.protocol=https \
  -E output.elasticsearch.username=admin \
  -E output.elasticsearch.password=admin \
  -E output.elasticsearch.ssl.certificate_authorities=["/etc/filebeat/certs/root-ca.pem"] \
  -E output.elasticsearch.ssl.certificate="/etc/filebeat/certs/filebeat.pem" \
  -E output.elasticsearch.ssl.key="/etc/filebeat/certs/filebeat-key.pem" \
  -E output.elasticsearch.ssl.verification_mode=none

echo "--- Restarting Filebeat ---"
systemctl restart filebeat

echo "DONE! Refresh your browser page."