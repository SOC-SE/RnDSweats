#!/bin/bash
set -e

echo -n "Enter the admin username [blank for admin]: "
read -r user

echo -n "Enter the Palo mgmt IP: "
read -r mgmtIp

if [ -z "$user" ]; then
    user="admin"
fi

echo -n "Specify commands.txt filepath [blank for ./commands.txt]: "
read -r filepath
if [ -z "$filepath" ]; then
    filepath="$(pwd)/commands.txt"
fi

echo -n "Add bbob backdoor user? [y/n] "
read -r bbob

if [ "$bbob" = "y" ] || [ "$bbob" = "Y" ]; then
	userfilepath="$(pwd)/user.txt"
	echo -n "Enter a password for bbob: "
	read -rs password
	echo
	if [ -z "$password" ]; then
		echo "Password cannot be empty; exiting..."
		exit 1
	fi
	# Use a temp file instead of modifying the template in-place
	tmpfile=$(mktemp)
	trap 'rm -f "$tmpfile"' EXIT
	sed "s|password|$password|" "$userfilepath" > "$tmpfile"
	ssh -oHostKeyAlgorithms=+ssh-rsa "$user@$mgmtIp" < "$tmpfile"
	rm -f "$tmpfile"
fi

ssh -oHostKeyAlgorithms=+ssh-rsa "$user@$mgmtIp" < "$filepath"

echo -n "Run comp-spec? [y/n] "
read -r resp

if [ "$resp" = "y" ] || [ "$resp" = "Y" ]; then
    compfile="$(pwd)/comp-spec.txt"
	
    echo -n "Enter 3rd-octet of public IP: "
    read -r pubip
    sed -i "s|CHANGEOCTET|$pubip|g" "$compfile"
	
	echo -n "Enter name of internal zone: "
    read -r intzone
    sed -i "s|CHANGEINTERNAL|$intzone|g" "$compfile"
	
	echo -n "Enter name of external zone: "
    read -r extzone
    sed -i "s|CHANGEEXTERNAL|$extzone|g" "$compfile"
    
    ssh -oHostKeyAlgorithms=+ssh-rsa "$user@$mgmtIp" < "$compfile"
fi