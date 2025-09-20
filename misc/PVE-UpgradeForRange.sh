#!/bin/bash
# This is me documenting (aka just pasting and adding small comments) the set of commands I use to upgrade the Proxmox servers for the Cyber Range. This is intended for upgrading from major versions 8 to 9.

#Doesn't do much in the script, but a great line just in case if you copy and paste the commands into a terminal
cd /etc/apt/sources.list.d

#Replace "bookworm" packages with the newer "trixie" ones. Aka, go from Debian 12 to Debian 13
sed -i 's/bookworm/trixie/g' /etc/apt/sources.list
sed -i 's/bookworm/trixie/g' /etc/apt/sources.list.d/pve-enterprise.list
sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list

#get the no subscription PVE mirrors for Trixie, if they don't exist in the sources.list file
grep -qxF 'deb http://download.proxmox.com/debian/pve trixie pve-no-subscription' /etc/apt/sources.list || echo 'deb http://download.proxmox.com/debian/pve trixie pve-no-subscription' | sudo tee -a /etc/apt/sources.list

#I ran into this issue where I didn't have the correct gpg key. This line pre-emptively fixes the possible issue
wget https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-trixie.gpg

#Remove unwanted mirrors
rm -f /etc/apt/sources.list.d/ceph.list
rm -f /etc/apt/sources.list.d/pve-install-repo.list
rm -f /etc/apt/sources.list.d/pvetest-for-beta.list

#get and upgrade the initial set of free packages
apt update && apt upgrade -y

#enable the enterprise mirrors - idk why this works or if it is 100% necessary, it's just part of the process I've been using so I'm leaving it in
#it may not be needed at all, I haven't bothered to do the testing to tell me if it is or isn't
sed -i 's/^#deb/deb/' /etc/apt/sources.list.d/pve-enterprise.list

#Full upgrade, this will switch over to the new major version
apt full-upgrade -y

#sanity-checking / house keeping
apt update
apt upgrade -y
apt autoremove -y
apt clean

#Final check to make sure it actually upgraded to the latest version
pveversion
