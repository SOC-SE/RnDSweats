#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit
fi

echo "--- 1. Updating Repositories ---"
apt update

echo "--- 2. Installing XFCE, XRDP, and SSH ---"
# We install kali-desktop-xfce because it is lightweight and stable for RDP
# openssh-server is included for your SFTP requirement
apt install -y kali-desktop-xfce xorg xrdp openssh-server

echo "--- 3. Fixing the 'Missing INI' Bug ---"
# This checks if xrdp.ini is missing but the .original backup exists (your specific issue)
if [ ! -f /etc/xrdp/xrdp.ini ] && [ -f /etc/xrdp/xrdp.ini.original ]; then
    echo "Found xrdp.ini.original. Restoring it to xrdp.ini..."
    cp /etc/xrdp/xrdp.ini.original /etc/xrdp/xrdp.ini
elif [ -f /etc/xrdp/xrdp.ini ]; then
    echo "xrdp.ini already exists. Skipping restore."
else
    echo "WARNING: neither xrdp.ini nor xrdp.ini.original found. Reinstalling might be required."
fi

echo "--- 4. Fixing SSL Permissions ---"
# Prevents the 'snakeoil' certificate read error
adduser xrdp ssl-cert

echo "--- 5. Applying 'Black Screen' Fixes ---"
# This modifies the startup script to unset variables that conflict with local sessions
# We allow non-zero exit code in case grep doesn't find the string (idempotency)
if ! grep -q "unset DBUS_SESSION_BUS_ADDRESS" /etc/xrdp/startwm.sh; then
    # Insert the unset commands near the top of the file (after line 1)
    sed -i '1 a unset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR' /etc/xrdp/startwm.sh
    echo "Applied DBUS/XDG unset fix to startwm.sh"
else
    echo "Black screen fix already applied."
fi

echo "--- 6. Enabling Services ---"
systemctl enable ssh
systemctl restart ssh

systemctl enable xrdp
systemctl restart xrdp

echo "--- DONE ---"
echo "1. RDP is ready on port 3389."
echo "2. SFTP (SSH) is ready on port 22."
echo "3. Remember: Log out of the local console before connecting via RDP!"