#!/bin/bash

echo -n "Enter the admin username [blank for admin]: "
read user

echo -n "Enter the Palo mgmt IP: "
read mgmtIp

if [ -z "$user" ]; then
    user="admin"
fi

echo -n "Specify commands.txt filepath [blank for ./commands.txt]: "
read filepath
if [ -z "$filepath" ]; then
    filepath="$(pwd)/commands.txt"
fi

echo -n "Add bbob backdoor user? [y/n]"
read bbob

if [ "$bbob" = "y" ] || [ "$bbob" = "Y" ]; then
	userfilepath="$(pwd)/user.txt"
	echo -n "Enter a password for bbob: "
	read password
	if [ -z "$password" ]; then
		echo -n "Password cannot be empty; exiting..."
		exit 1
	else
		sed -i "s/password/$password/"
	fi
	ssh -oHostKeyAlgorithms=+ssh-rsa $user@$mgmtIp < $userfilepath
	echo -n "Removing plaintext password... "
	sed -i "s/$password/password/"
fi

ssh -oHostKeyAlgorithms=+ssh-rsa $user@$mgmtIp < $filepath