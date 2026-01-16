#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit
fi

echo "--- 1. Updating Repositories ---"
apt update

echo "--- 2. Installing XFCE, XRDP, and SSH ---"
# CHANGED: 'xfce4' is the generic package name for Parrot/Debian
apt install -y xfce4 xorg xrdp openssh-server

echo "--- 3. Configuring Session ---"
# NEW: Force XRDP to use XFCE specifically
echo "xfce4-session" > /home/$SUDO_USER/.xsession
chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.xsession
# Also set it for root just in case (though you shouldn't RDP as root)
echo "xfce4-session" > /root/.xsession

echo "--- 4. Checking for Config Quirks ---"
# The 'missing ini' bug is rare on Parrot, but this safety check won't hurt.
if [ ! -f /etc/xrdp/xrdp.ini ] && [ -f /etc/xrdp/xrdp.ini.original ]; then
    echo "Restoring xrdp.ini from backup..."
    cp /etc/xrdp/xrdp.ini.original /etc/xrdp/xrdp.ini
fi

echo "--- 5. Fixing SSL Permissions ---"
adduser xrdp ssl-cert

echo "--- 6. Applying 'Black Screen' Fixes ---"
if ! grep -q "unset DBUS_SESSION_BUS_ADDRESS" /etc/xrdp/startwm.sh; then
    sed -i '1 a unset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR' /etc/xrdp/startwm.sh
    echo "Applied DBUS/XDG unset fix to startwm.sh"
fi

echo "--- 7. Enabling Services ---"
systemctl enable ssh
systemctl restart ssh

systemctl enable xrdp
systemctl restart xrdp

echo "--- DONE ---"
echo "1. RDP is ready on port 3389 (Using XFCE Desktop)."
echo "2. SFTP is ready on port 22."