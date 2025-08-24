#!/usr/bin/env python
import sys
import json
import datetime

# The log file where we will write the new event
LOG_FILE = "/var/ossec/logs/custom-fim.log"

# Get the alert data from Wazuh
alert_json = sys.stdin.read()
alert = json.loads(alert_json)

# Extract relevant details
try:
    file_path = alert["parameters"]["alert"]["syscheck"]["path"]
    diff_data = alert["parameters"]["alert"]["syscheck"]["diff"]
    agent_name = alert["parameters"]["agent"]["name"]
    agent_id = alert["parameters"]["agent"]["id"]
    rule_desc = alert["parameters"]["alert"]["rule"]["description"]

    # Create a new JSON object for our custom log
    custom_event = {
        "wazuh": {
            "event_type": "custom-fim-alert",
            "agent": {
                "name": agent_name,
                "id": agent_id
            },
            "fim": {
                "path": file_path,
                "diff": diff_data,
                "original_rule": rule_desc
            }
        }
    }

    # Write the JSON event to our custom log file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(custom_event) + "\n")

except KeyError:
    # Handle cases where the alert might not have the expected structure
    pass

sys.exit(0)
