#!/bin/bash
set -euo pipefail
# Wazuh - Yara active response
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#------------------------- Gather parameters -------------------------#

# Extra arguments
read -r INPUT_JSON

# Parse JSON input (with fallback defaults)
YARA_PATH="/usr/bin"
YARA_RULES="/opt/yara-rules/compiled_community_rules.yarac"
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)
QUARANTINE_PATH="/tmp/quarantined"

# Set LOG_FILE path
LOG_FILE="/var/ossec/logs/active-responses.log"

# Ensure quarantine directory exists
mkdir -p "$QUARANTINE_PATH"

# Wait for file to finish being written (check size stability)
size=0
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
while [ "${size}" -ne "${actual_size}" ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo "0")
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -C -w -r -f -m "$YARA_RULES" "$FILENAME")"

if [[ -n "$yara_output" ]]; then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"
    done <<< "$yara_output"

    # Generate timestamp and extract filename
    DATE=$(date "+%F_%H-%M")
    JUSTNAME=$(basename "$FILENAME")
    QUARANTINED_FILE="${QUARANTINE_PATH}/${JUSTNAME}-${DATE}"

    # Move file to quarantine
    /usr/bin/mv -f "$FILENAME" "$QUARANTINED_FILE"

    # Make quarantined file immutable
    /usr/bin/chattr +i "$QUARANTINED_FILE" 2>/dev/null || true

    echo "wazuh-yara: $FILENAME moved to $QUARANTINED_FILE" >> "${LOG_FILE}"
fi

exit 0;