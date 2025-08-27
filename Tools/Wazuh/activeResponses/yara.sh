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
#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) SOCFortress, LLP.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Gather parameters -------------------------#

# The filename is passed as the first argument by the <expect> tag
FILENAME="$1"

# The extra_args are passed as subsequent arguments
YARA_PATH="$3"
YARA_RULES="$5"

QUARANTINE_PATH="/tmp/quarantined"

# Set LOG_FILE to the standard, absolute path
LOG_FILE="/var/ossec/logs/active-responses.log"

# Check if FILENAME is valid
if [ -z "$FILENAME" ]; then
    echo "wazuh-yara: ERROR - Filename not provided." >> ${LOG_FILE}
    exit 1;
fi

# Wait for the file to be fully written (no change from original script)
size=0
actual_size=$(stat -c %s "${FILENAME}")
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}")
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
    /usr/bin/mv -f "$FILENAME" "${QUARANTINE_PATH}/"
    FILEBASE=$(/usr/bin/basename "$FILENAME")
    /usr/bin/chattr +i "${QUARANTINE_PATH}/${FILEBASE}"
    /usr/bin/echo "wazuh-yara: $FILENAME moved to ${QUARANTINE_PATH}" >> ${LOG_FILE}
fi

exit 0;
QUARANTINE_PATH="/tmp/quarantined"

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

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
    /usr/bin/mv -f $FILENAME ${QUARANTINE_PATH}
    FILEBASE=$(/usr/bin/basename $FILENAME)
    /usr/bin/chattr -R +i ${QUARANTINE_PATH}/${FILEBASE}
    /usr/bin/echo "wazuh-yara: $FILENAME moved to ${QUARANTINE_PATH}" >> ${LOG_FILE}
fi

exit 0;