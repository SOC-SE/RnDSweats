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

ssh -oHostKeyAlgorithms=+ssh-rsa $user@$mgmtIp < $filepath