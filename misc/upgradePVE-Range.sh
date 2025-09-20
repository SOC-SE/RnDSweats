#!/bin/bash
# This is me documenting (aka just pasting and adding small comments) the set of commands I use to upgrade the Proxmox servers for the Cyber Range. This is intended for upgrading from major versions 8 to 9.

#Doesn't do much in the script, but a great line just in case if you copy and paste the commands into a terminal
cd /etc/apt/sources.list.d
#Replace "bookworm" packages with the newer "trixie" ones. Aka, go from Debian 12 to Debian 13
sed -i 's/bookworm/trixie/g' /etc/apt/sources.list
sed -i 's/bookworm/trixie/g' /etc/apt/sources.list.d/pve-enterprise.list
sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list
#I ran into this issue where I didn't have the correct gpg key. This line pre-emptively fixes the possible issue
wget https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-trixie.gpg
#We don't use ceph but it's randomly installed on some servers. Might as well simplify our process and remove the mirror
rm -f /etc/apt/sources.list.d/ceph.list
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
