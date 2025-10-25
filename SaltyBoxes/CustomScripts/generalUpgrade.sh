#!/bin/bash
#
# General Linux Update & Upgrade Preparation Script
#
# This script detects the OS (Ubuntu, Fedora, Oracle Linux) from your topology
# and performs the following actions:
# 1. A full system package update and upgrade to the latest minor release.
# 2. Installs the necessary tools for a future major OS release upgrade.
# 3. Creates a completion marker file in /home.
#
# MUST BE RUN AS ROOT OR WITH SUDO.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Functions ---

create_completion_file() {
  # Get the hostname
  HOST_NAME=$(hostname)
  echo "-------------------------------------------------"
  echo "Creating upgrade completion marker..."
  
  # Write the completion file to /home. This assumes /home is writable by root.
  echo "$HOST_NAME upgrade complete" > /home/${HOST_NAME}_upgrade_complete.txt
  
  echo "Completion marker created at /home/${HOST_NAME}_upgrade_complete.txt"
}

update_ubuntu() {
  echo "Detected Ubuntu. Running apt..."
  
  # Ensure the environment is non-interactive
  export DEBIAN_FRONTEND=noninteractive
  
  # Update package lists
  apt update
  
  # Perform a full upgrade (handles kernel, etc., better than 'upgrade')
  apt dist-upgrade -y
  
  echo "Installing OS upgrade tool (update-manager-core)..."
  # This package is required for 'do-release-upgrade'
  apt install -y update-manager-core
  
  # Clean up cached packages
  apt autoremove -y
  apt clean
  
  create_completion_file
  
  echo "-------------------------------------------------"
  echo "Ubuntu update complete."
  echo "When ready to upgrade to the next major release, run: sudo do-release-upgrade"
}

update_rhel_family() {
  DISTRO_NAME=$1
  echo "Detected $DISTRO_NAME. Running dnf..."
  
  # General upgrade to the latest minor release for this major version
  # This removes the previous '--releasever=9.6' lock
  dnf upgrade -y
  
  echo "Installing DNF system upgrade plugin..."
  # This plugin is used for major version upgrades (e.g., OL 9->10 or Fedora 42->43)
  dnf install -y dnf-plugin-system-upgrade
  
  echo "Cleaning up DNF cache..."
  dnf clean all
  
  create_completion_file
  
  echo "-------------------------------------------------"
  echo "$DISTRO_NAME update complete."
  echo "When ready to upgrade to the next major release:"
  echo "sudo dnf system-upgrade download --releasever=<version>"
  echo "(e.g., --releasever=43 for Fedora, --releasever=10 for Oracle Linux)"
}

# --- Main Script ---

main() {
  # Check for root privileges
  if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo or as root."
    exit 1
  fi
  
  # Check for /etc/os-release
  if [ ! -f /etc/os-release ]; then
    echo "Error: Cannot determine OS. /etc/os-release not found."
    exit 1
  fi
  
  # Source OS info variables (ID, PRETTY_NAME, etc.)
  . /etc/os-release
  
  echo "Starting general system update for $PRETTY_NAME..."
  
  # Case statement to handle different Linux IDs
  case "$ID" in
    ubuntu)
      update_ubuntu
      ;;
      
    fedora)
      update_rhel_family "Fedora"
      ;;
      
    ol)
      update_rhel_family "Oracle Linux"
      ;;
      
    *)
      echo "Unsupported Linux distribution: $ID ($PRETTY_NAME)"
      echo "This script only supports Ubuntu, Fedora, and Oracle Linux as shown in the topology."
      exit 1
      ;;
  esac
  
  echo "-------------------------------------------------"
  echo "All operations complete."
  echo "It is highly recommended to REBOOT your system now."
}

# Run the main function
main
