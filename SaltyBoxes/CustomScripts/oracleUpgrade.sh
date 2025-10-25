#!/bin/bash
#
# This script fully updates an Oracle Linux 9 system to version 9.6
# and prepares it for a future major OS upgrade (e.g., from OL9 to OL10)
# by installing the system upgrade plugin.
#
# Run this script with sudo privileges or as root.

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting system upgrade to Oracle Linux 9.6..."
# Upgrade all packages to the 9.6 release version.
# This will update the system to 9.6 and stop there,
# even if a newer minor release (e.g., 9.7) is available.
sudo dnf upgrade --releasever=9.6 -y

echo "Upgrade to 9.6 complete."
echo "-------------------------------------------------"
echo "Installing DNF system upgrade plugin..."
# This plugin is used to perform major version upgrades
sudo dnf install -y dnf-plugin-system-upgrade

echo "Plugin installation complete."
echo "-------------------------------------------------"
echo "Cleaning up DNF cache..."
sudo dnf clean all

echo "-------------------------------------------------"
echo "Creating upgrade completion marker..."
# Create a file in /home with the machine's hostname to mark completion.
# This requires sudo as /home is typically root-owned.
HOST_NAME=$(hostname)
echo "$HOST_NAME upgrade complete" | sudo tee /home/${HOST_NAME}_upgrade_complete.txt > /dev/null

echo "Completion marker created at /home/${HOST_NAME}_upgrade_complete.txt"
echo "-------------------------------------------------"
echo "Update and preparation complete."
echo ""
echo "It is highly recommended to REBOOT your system now to apply kernel updates."
echo ""
echo "When you are ready to perform a major OS upgrade (e.g., to OL10),"
echo "you can start the process by running:"
echo "sudo dnf system-upgrade download --releasever=<version>"
echo "(Replace <version> with the target release, e.g., 10)"

