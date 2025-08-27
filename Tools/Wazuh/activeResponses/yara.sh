#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)
YARA_PATH="/usr/bin"
YARA_RULES="/opt/yara-rules/compiled_community_rules.yarac"
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)
QUARANTINE_PATH="/tmp/quarantined"

# Set LOG_FILE path
LOG_FILE="/var/ossec/logs/active-responses.log"

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
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

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
    DATE=`date "+%F_%H-%M"`
    JUSTNAME=$(echo $FILENAME | awk '{n=split($NF,a,"/");print a[n]}')
    /usr/bin/mv -f $FILENAME "$QUARANTINE_PATH"/"$JUSTNAME-$DATE"
    FILEBASE=$(/usr/bin/basename $FILENAME-$DATE)
    /usr/bin/chattr -R +i ${QUARANTINE_PATH}/${FILEBASE}
    /usr/bin/echo "wazuh-yara: $FILENAME moved to ${QUARANTINE_PATH}" >> ${LOG_FILE}
fi

exit 0;