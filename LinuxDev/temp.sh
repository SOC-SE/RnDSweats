#!/bin/bash

cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.overwrite_keys: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["127.0.0.1:9200"]
  protocol: https
  username: "admin"
  password: "Changeme1!"
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.verification_mode: none
  # Defines the target index name explicitly
  index: "wazuh-alerts-4.x-%{+yyyy.MM.dd}"

setup.template.name: "wazuh"
setup.template.pattern: "wazuh-alerts-*"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.template.overwrite: true
setup.ilm.enabled: false
seccomp.enabled: false
EOF