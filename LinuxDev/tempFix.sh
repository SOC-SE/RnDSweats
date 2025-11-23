# 1. Generate hash for "Changeme1!"
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "Changeme1!" > /tmp/hash_new.txt
NEW_HASH=$(cat /tmp/hash_new.txt)

# 2. Update admin password in internal_users.yml (Be specific to admin user)
# We use a precise sed command to only target the admin user's hash
sed -i "/^admin:/,/^  hash:/ s|hash:.*|hash: \"$NEW_HASH\"|" /etc/wazuh-indexer/opensearch-security/internal_users.yml

# 3. Apply changes to the Database (The critical step)
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -p 9200 \
  -icl \
  -h 127.0.0.1

# 4. Update Dashboard Config to match
sed -i 's/opensearch.password:.*/opensearch.password: Changeme1!/' /etc/wazuh-dashboard/opensearch_dashboards.yml

# 5. Restart Dashboard
systemctl restart wazuh-dashboard