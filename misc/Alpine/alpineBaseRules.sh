#!/bin/bash

cat <<'END_CAT'
    ___    __      _               _____      __            
   /   |  / /___  (_)___  ___     / ___/___  / /___  ______ 
  / /| | / / __ \/ / __ \/ _ \    \__ \/ _ \/ __/ / / / __ \
 / ___ |/ / /_/ / / / / /  __/   ___/ /  __/ /_/ /_/ / /_/ /
/_/  |_/_/ .___/_/_/ /_/\___/   /____/\___/\__/\__,_/ .___/ 
        /_/                                        /_/  
END_CAT

sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT

sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Test if iptables-save works
sudo iptables-save > ./ruleset.rules
if [ $? -eq 0 ]; then
	echo -e "iptables-save is installed"
	echo -e "current ruleset saved in ./ruleset.rules"
else
	echo -e "iptables-save is not installed"
fi

echo "Set default policies to drop? (y/n)"
read response
if [ "$response" == "y" ]; then
	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP
fi

sudo iptables -nvL --line-numbers