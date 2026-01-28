#!/bin/sh

# Get/fix docker image
#git clone https://github.com/julienyvenat/docker-suricata.git ./docker-suricata

cd docker-suricata
sed -i 's/RUN apk add python py-pip/RUN apk add python3 py3-pip/' alpine/Dockerfile/Dockerfile
sed -i 's/RUN pip install suricata-update/RUN pip install suricata-update --break-system-packages' alpine/Dockerfile/Dockerfile

# Start Suricata in background
docker compose up -d --build --force-recreate

# Add iptables forwarding
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE
iptables -I FORWARD -j NFQUEUE
