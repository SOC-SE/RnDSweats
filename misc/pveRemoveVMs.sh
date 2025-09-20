#!/bin/bash

# A simple script to stop and destroy a list of Proxmox VMs.

# --- WARNING ---
# This script will permanently delete the specified virtual machines and all their data.
# This action is IRREVERSIBLE.
# Make sure you have backups of any important data before proceeding.

# Prompt user for the list of VM IDs
read -p "Please enter the VM IDs you want to delete (separated by spaces): " VM_IDS

# Check if the user entered any IDs
if [ -z "$VM_IDS" ]; then
    echo "No VM IDs were entered. Exiting."
    exit 0
fi

# Confirmation prompt
echo "" # Add a newline for better readability
echo "You are about to permanently delete the following VM IDs:"
echo "$VM_IDS"
read -p "Are you sure you want to continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Deletion cancelled."
    exit 0
fi

# Loop through each ID in the list
for ID in $VM_IDS; do
    echo "----------------------------------------"
    echo "Processing VM ID: $ID"

    # Check if VM exists before trying to stop/destroy
    if qm status $ID > /dev/null 2>&1; then
        echo "Attempting to stop VM $ID..."
        qm stop $ID

        # Optional: Wait a few seconds to ensure the VM has time to shut down
        sleep 5

        echo "Destroying VM $ID..."
        # The --purge flag also removes the VM from backup/HA configurations
        qm destroy $ID --purge
        echo "VM $ID has been deleted."
    else
        echo "VM ID $ID not found. Skipping."
    fi
done

echo "----------------------------------------"
echo "Script finished."

