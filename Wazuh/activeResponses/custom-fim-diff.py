#!/usr/bin/env python
import sys
import json
import requests

# Get the alert data from Wazuh
alert_json = sys.stdin.read()
alert = json.loads(alert_json)

# Extract relevant details
file_path = alert["parameters"]["alert"]["syscheck"]["path"]
diff_data = alert["parameters"]["alert"]["syscheck"]["diff"]
agent_name = alert["parameters"]["agent"]["name"]
rule_desc = alert["parameters"]["alert"]["rule"]["description"]

# Your Slack Webhook URL
slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Format the message for Slack
slack_message = {
    "text": f"🚨 *Wazuh FIM Alert on {agent_name}*",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"File Changed: {file_path}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:* {rule_desc}\n*Agent:* {agent_name}"
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Changes Detected:*\n```{diff_data}```"
            }
        }
    ]
}

# Send the message to Slack
requests.post(slack_webhook_url, json=slack_message)

sys.exit(0)
