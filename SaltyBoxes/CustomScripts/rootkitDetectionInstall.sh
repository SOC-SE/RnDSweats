#!/bin/bash
#
# This script installs rkhunter and chkrootkit on Debian/Ubuntu and
# RHEL/Fedora/Oracle Linux systems.
#
# It will automatically detect the package manager and, if necessary,
# install the EPEL repository on RHEL-based systems.
#
# MUST BE RUN AS ROOT OR WITH SUDO.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Root Check ---
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root or with sudo."
  exit 1
fi

echo "Starting installation of rootkit detection tools..."

# --- Distro Detection & Installation ---

if command -v apt-get &> /dev/null; then
    # --- Debian / Ubuntu ---
    echo "[+] Detected apt package manager (Debian/Ubuntu-based)."

    
    echo "[*] Installing rkhunter and chkrootkit..."
    apt-get install -y rkhunter chkrootkit

elif command -v dnf &> /dev/null; then
    # --- Fedora / RHEL 9+ / Oracle 9+ ---
    echo "[+] Detected dnf package manager (Fedora/RHEL/Oracle-based)."
    
    echo "[*] Installing EPEL repository (needed for these tools)..."
    dnf install -y epel-release
    
    echo "[*] Installing rkhunter and chkrootkit..."
    dnf install -y rkhunter chkrootkit

elif command -v yum &> /dev/null; then
    # --- RHEL 7/8 / Oracle 7/8 ---
    echo "[+] Detected yum package manager (RHEL/Oracle-based)."
    
    echo "[*] Installing EPEL repository (needed for these tools)..."
    yum install -y epel-release
    
    echo "[*] Installing rkhunter and chkrootkit..."
    yum install -y rkhunter chkrootkit
    
else
    echo "Error: Could not detect 'apt', 'dnf', or 'yum' package manager."
    echo "Installation failed."
    exit 1
fi

echo ""
echo "---[ Installation Complete ]---"
echo "Successfully installed rkhunter and chkrootkit."
echo ""
echo "IMPORTANT: Before your first scan, you MUST update rkhunter's database:"
echo "  sudo rkhunter --propupd"
echo ""
echo "After that, you can run your first scan with:"
echo "  sudo rkhunter --check"
echo "  sudo chkrootkit"
