#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit
fi

echo "--- 1. Updating Repositories ---"
apt update

echo "--- 2. Installing Desktop & Remote Tools ---"
# Debian needs xfce4-goodies for standard tools (terminal, archive manager, etc.)
# curl and wget are added as they are often missing in minimal installs
apt install -y xfce4 xfce4-goodies xorg xrdp openssh-server curl wget

echo "--- 3. Configuring Session (Force XFCE) ---"
# Debian alternatives system can sometimes pick the wrong session. 
# We force XFCE for the current user and root to be safe.
if [ -n "$SUDO_USER" ]; then
    echo "xfce4-session" > /home/$SUDO_USER/.xsession
    chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.xsession
fi
echo "xfce4-session" > /root/.xsession

echo "--- 4. Fixing SSL Permissions ---"
# Standard Debian security restricts access to ssl-cert-snakeoil.key
adduser xrdp ssl-cert

echo "--- 5. Applying 'Black Screen' Fixes ---"
# Debian 13 is strict with Polkit/DBus. This fix is mandatory.
if ! grep -q "unset DBUS_SESSION_BUS_ADDRESS" /etc/xrdp/startwm.sh; then
    sed -i '1 a unset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR' /etc/xrdp/startwm.sh
    echo "Applied DBUS/XDG unset fix to startwm.sh"
fi

echo "--- 6. Checking Config Health ---"
# This checks for the 'renamed config' bug. 
# It is rare in standard Debian, but we check just to be safe.
if [ ! -f /etc/xrdp/xrdp.ini ] && [ -f /etc/xrdp/xrdp.ini.original ]; then
    echo "Restoring xrdp.ini from backup..."
    cp /etc/xrdp/xrdp.ini.original /etc/xrdp/xrdp.ini
fi

echo "--- 7. Enabling Services ---"
systemctl enable ssh
systemctl restart ssh

systemctl enable xrdp
systemctl restart xrdp

echo "--- DONE ---"
echo "1. RDP is ready on port 3389."
echo "2. SFTP is ready on port 22."
echo "3. Note: If you installed a minimal Debian, you might need to reboot once."