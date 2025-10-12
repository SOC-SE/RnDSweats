#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

read -p "Enter the first Caldera URL: " server1
read -p "Enter the first agent process name: " agent1
read -p "Enter the second Caldera URL: " server2
read -p "Enter the second Caldera's socket: " socket
read -p "Enter the second agent process name: " agent2


bash sandcat $server1 $agent1
bash manx $server2 $socket $agent2

echo "agents installed, cleaning up"
sleep 5
rm -f $agent1 $agent2 
echo "cleaning finished"