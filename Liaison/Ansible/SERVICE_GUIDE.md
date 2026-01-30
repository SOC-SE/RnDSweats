# Liaison Service Guide

Post-installation usage guide for all services deployed by the Liaison Ansible playbook.

---

## Table of Contents
- [VPN Services](#vpn-services)
  - [WireGuard](#wireguard)
  - [OpenVPN](#openvpn)
  - [SoftEther](#softether)
- [Docker](#docker)
- [Network Scanning](#network-scanning)
  - [Subnet Ping](#subnet-ping)
  - [Nmap Scanner](#nmap-scanner)
  - [TShark Tools](#tshark-tools)
- [Security Tools](#security-tools)
  - [FIM Monitor](#fim-monitor)
  - [Honeypot (Endlessh)](#honeypot-endlessh)
  - [IDS (Suricata)](#ids-suricata)
  - [Rootkit Scanner](#rootkit-scanner)
- [System Tools](#system-tools)
  - [NTP (Chrony)](#ntp-chrony)
  - [PowerShell](#powershell)
  - [System Enumeration](#system-enumeration)
- [System Hardening](#system-hardening)
  - [Firewall (iptables)](#firewall-iptables)
  - [XRDP Server](#xrdp-server-remote-desktop)
  - [ClamAV Antivirus](#clamav-antivirus)
  - [Backup & Restore](#backup--restore)
  - [User Audit](#user-audit)
  - [Extended Docker Services](#extended-docker-services)
- [Removal & Uninstall](#removal--uninstall)
- [Quick Reference](#quick-reference)
- [Troubleshooting](#troubleshooting)

---

## VPN Services

### WireGuard

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=wireguard
```

**View Server Keys:**
```bash
# View server public key (share with clients)
sudo cat /etc/wireguard/server_public.key

# View server private key (keep secret)
sudo cat /etc/wireguard/server_private.key
```

**View Client Keys:**
```bash
# View client public key
sudo cat /etc/wireguard/client_public.key

# View client private key (for client config)
sudo cat /etc/wireguard/client_private.key
```

**Manage WireGuard Service:**
```bash
# Start WireGuard
sudo systemctl start wg-quick@wg0

# Stop WireGuard
sudo systemctl stop wg-quick@wg0

# Restart WireGuard
sudo systemctl restart wg-quick@wg0

# Check status
sudo systemctl status wg-quick@wg0

# Enable on boot
sudo systemctl enable wg-quick@wg0
```

**WireGuard Commands:**
```bash
# Show interface status and connected peers
sudo wg show

# Show detailed stats
sudo wg show wg0

# Bring interface up manually
sudo wg-quick up wg0

# Bring interface down
sudo wg-quick down wg0
```

**View/Edit Configuration:**
```bash
# View server config
sudo cat /etc/wireguard/wg0.conf

# Edit config (restart after changes)
sudo nano /etc/wireguard/wg0.conf
```

**Client Configuration Template:**
Create this on your client device:
```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
Endpoint = <server_ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Add a New Peer (Client):**
```bash
# Generate new client keys
wg genkey | tee client2_private.key | wg pubkey > client2_public.key

# Add peer to running interface
sudo wg set wg0 peer $(cat client2_public.key) allowed-ips 10.0.0.3/32

# CRITICAL: Save configuration to disk to persist across reboots
sudo wg-quick save wg0
```

---

### OpenVPN

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=openvpn
```

**View PKI Certificates:**
```bash
# Server certificate
sudo cat /etc/openvpn/easy-rsa/pki/issued/server.crt

# CA certificate (needed by clients)
sudo cat /etc/openvpn/ca.crt

# List all issued certificates
ls -la /etc/openvpn/easy-rsa/pki/issued/
```

**Manage OpenVPN Service:**
```bash
# Start OpenVPN server
sudo systemctl start openvpn@server

# Stop OpenVPN server
sudo systemctl stop openvpn@server

# Restart OpenVPN
sudo systemctl restart openvpn@server

# Check status
sudo systemctl status openvpn@server

# View logs
sudo journalctl -u openvpn@server -f
```

**Generate Client Certificate:**
```bash
cd /etc/openvpn/easy-rsa
sudo ./easyrsa gen-req client1 nopass
sudo ./easyrsa sign-req client client1

# ESSENTIAL: Retrieve files needed for client config
# Private Key (keep secret)
sudo cat /etc/openvpn/easy-rsa/pki/private/client1.key

# Certificate
sudo cat /etc/openvpn/easy-rsa/pki/issued/client1.crt
```

**View Server Configuration:**
```bash
sudo cat /etc/openvpn/server.conf
```

**Client Configuration Template:**
```ini
client
dev tun
proto udp
remote <server_ip> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
verb 3
```

**Check Connected Clients:**
```bash
# View status log
sudo cat /var/log/openvpn/status.log

# Or if using management interface
echo "status" | nc localhost 7505
```

---

### SoftEther

**Installation:**

> [!TIP]
> If your user requires a sudo password, add `-K` to prompt for it upfront.

```bash
# Standard installation
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=softether -e softether_server_password=YourPassword

# With sudo password prompt (recommended)
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=softether -e softether_server_password=YourPassword -K
```

**Manage SoftEther Service:**
```bash
# Start SoftEther
sudo systemctl start vpnserver

# Stop SoftEther
sudo systemctl stop vpnserver

# Restart SoftEther
sudo systemctl restart vpnserver

# Check status
sudo systemctl status vpnserver
```

**SoftEther Command Line (vpncmd):**
```bash
# Enter server management mode
sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword

# Common commands inside vpncmd:
# List virtual hubs
HubList

# Create new hub
HubCreate MyHub

# Set hub password
HubSetPassword MyHub

# Create user
UserCreate username

# Set user password
UserPasswordSet username

# List users
UserList

# View server status
ServerStatusGet

# Exit vpncmd
exit
```

**Quick Setup Commands:**
```bash
# One-liner to check server status
sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword /CMD ServerStatusGet

# List all hubs
sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword /CMD HubList
```

**View Logs:**
```bash
# Server logs
sudo tail -f /opt/vpnserver/server_log/*.log

# Security logs
sudo tail -f /opt/vpnserver/security_log/*.log
```

**Ports Used:**
- 443 (HTTPS/SSL-VPN)
- 992 (SSL-VPN alternate)
- 1194 (OpenVPN compatible)
- 5555 (SoftEther default)

---

## Docker

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=docker
```

**Basic Docker Commands:**
```bash
# Check Docker is running
sudo systemctl status docker

# View running containers (use sudo unless user is in docker group)
sudo docker ps

# View all containers (including stopped)
sudo docker ps -a

# View images
sudo docker images

# Pull an image
sudo docker pull nginx:latest

# Run a container
sudo docker run -d --name mycontainer -p 8080:80 nginx

# Stop a container
sudo docker stop mycontainer

# Start a container
sudo docker start mycontainer

# Remove a container
sudo docker rm mycontainer

# Remove an image
sudo docker rmi nginx:latest
```

**Docker Compose:**
```bash
# Start services defined in docker-compose.yml
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Rebuild and start
docker compose up -d --build
```

**Container Management:**
```bash
# Execute command in running container
docker exec -it mycontainer /bin/bash

# View container logs
docker logs mycontainer
docker logs -f mycontainer  # Follow logs

# Inspect container
docker inspect mycontainer

# View container resource usage
docker stats
```

**Cleanup Commands:**
```bash
# Remove all stopped containers
docker container prune

# Remove unused images
docker image prune

# Remove all unused data (containers, networks, images)
docker system prune -a

# View disk usage
docker system df
```

---

## Network Scanning

### Subnet Ping

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=subnet -e subnet_cidr=192.168.1.0/24
```

**Manual Subnet Scanning:**
```bash
# Basic ping sweep
nmap -sn 192.168.1.0/24

# Ping sweep with hostnames
nmap -sn -R 192.168.1.0/24

# Fast ping sweep (no DNS resolution)
nmap -sn -n 192.168.1.0/24

# Save results to file
nmap -sn 192.168.1.0/24 -oN scan_results.txt

# Output in all formats
nmap -sn 192.168.1.0/24 -oA subnet_scan
```

**View Scan Results:**
```bash
# Results are saved to liaison log directory
cat /var/log/liaison/subnet-scan-*.nmap
```

---

### Nmap Scanner

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=nmap -e nmap_type=aggressive -e nmap_target=10.0.0.1
```

**Scan Types Available:**
```bash
# Ping scan (host discovery)
nmap -sn 10.0.0.1

# Port scan (all ports)
nmap -p- -T4 10.0.0.1

# Service version detection
nmap -sV 10.0.0.1

# OS detection (Requires Root)
sudo nmap -O 10.0.0.1

# Vulnerability scan
nmap --script vuln 10.0.0.1

# Aggressive scan (OS, version, scripts, traceroute)
sudo nmap -A 10.0.0.1
```

**Common Nmap Commands:**
```bash
# Quick scan of common ports
nmap -F 10.0.0.1

# Scan specific ports
nmap -p 22,80,443 10.0.0.1

# Scan port range
nmap -p 1-1000 10.0.0.1

# UDP scan (Top 20 ports - full UDP is very slow)
sudo nmap -sU --top-ports 20 10.0.0.1

# Stealth SYN scan (Requires Root)
sudo nmap -sS 10.0.0.1

# Script scan (default scripts)
nmap -sC 10.0.0.1

# Save results
nmap -A 10.0.0.1 -oA /var/log/liaison/nmap_logs/full_scan
```

**View Results:**
```bash
# Nmap results location
ls -la /var/log/liaison/nmap_logs/

# View latest scan
cat /var/log/liaison/nmap_logs/scan-*.nmap
```

---

### TShark Tools

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=tshark -e tshark_action=capture
```

**Basic TShark Commands:**
```bash
# List available interfaces
tshark -D

# NOTE: Interface names vary (eth0, ens18, enp3s0, etc.)
# Find your interface first:
ip a

# Capture on specific interface (replace <interface> with yours)
sudo tshark -i <interface>

# Capture with packet count limit
sudo tshark -i <interface> -c 100

# Capture and save to file
sudo tshark -i <interface> -w capture.pcap

# Capture with time limit (seconds)
sudo tshark -i <interface> -a duration:60 -w capture.pcap
```

**Capture Filters (BPF syntax):**
```bash
# Capture only TCP traffic
sudo tshark -i eth0 -f "tcp"

# Capture specific port
sudo tshark -i eth0 -f "port 80"

# Capture specific host
sudo tshark -i eth0 -f "host 192.168.1.100"

# Capture HTTP traffic
sudo tshark -i eth0 -f "tcp port 80 or tcp port 443"

# Exclude SSH (useful when remote)
sudo tshark -i eth0 -f "not port 22"
```

**Reading PCAP Files:**
```bash
# Read pcap file
tshark -r capture.pcap

# Read with packet limit
tshark -r capture.pcap -c 50

# Read with display filter
tshark -r capture.pcap -Y "http"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

**Display Filters:**
```bash
# Filter HTTP requests
tshark -r capture.pcap -Y "http.request"

# Filter by IP
tshark -r capture.pcap -Y "ip.addr == 192.168.1.100"

# Filter DNS queries
tshark -r capture.pcap -Y "dns.qry.name"

# Filter failed connections
tshark -r capture.pcap -Y "tcp.flags.reset == 1"
```

**Analysis Commands:**
```bash
# Protocol hierarchy statistics
tshark -r capture.pcap -q -z io,phs

# Conversation statistics
tshark -r capture.pcap -q -z conv,ip

# HTTP statistics
tshark -r capture.pcap -q -z http,tree

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

**View Captured Files:**
```bash
cat /var/log/liaison/capture.pcap  # Binary - use tshark to read
tshark -r /var/log/liaison/capture.pcap
```

---

## Security Tools

### FIM Monitor

**Installation:**
```bash
# Start monitoring
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=1

# List active monitors
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=2

# Stop monitoring
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=3

# View changes
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=4
```

**FIM Choices:**
| Choice | Action |
|--------|--------|
| 1 | Create baseline and start monitoring |
| 2 | List active FIM sessions |
| 3 | Stop and remove a monitor |
| 4 | View detected changes |

**Manual FIM Commands:**
```bash
# View active FIM sessions
ls -la /var/log/liaison/fim/

# View baseline for a session
cat /var/log/liaison/fim/<session_id>/baseline.txt

# View detected changes
cat /var/log/liaison/fim/<session_id>/changes.log

# View FIM cron jobs
crontab -l | grep FIM

# Manually check for changes
find /etc -type f -exec md5sum {} + > /tmp/current.txt
diff /var/log/liaison/fim/<session_id>/baseline.txt /tmp/current.txt
```

**Create Manual Baseline:**
```bash
# IMPORTANT: Use /var/log/liaison/fim/ for persistence (NOT /tmp - cleared on reboot!)
sudo mkdir -p /var/log/liaison/fim

# Create baseline of /etc directory
sudo find /etc -type f -exec md5sum {} + 2>/dev/null > /var/log/liaison/fim/etc_baseline.txt

# Compare later
find /etc -type f -exec md5sum {} + 2>/dev/null > /tmp/etc_current.txt
diff /var/log/liaison/fim/etc_baseline.txt /tmp/etc_current.txt
```

---

### Honeypot (Endlessh)

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=honeypot
```

**Manage Endlessh Service:**
```bash
# Start Endlessh
sudo systemctl start endlessh

# Stop Endlessh
sudo systemctl stop endlessh

# Check status
sudo systemctl status endlessh

# View logs
sudo journalctl -u endlessh -f
```

**View Configuration:**
```bash
# View config
cat /etc/endlessh/config

# Default config options:
# Port 2222          - Port to listen on
# Delay 10000        - Milliseconds between sends
# MaxLineLength 32   - Max banner line length
# MaxClients 4096    - Max concurrent clients
# LogLevel 1         - 0=silent, 1=connections, 2=verbose
```

**Monitor Trapped Connections:**
```bash
# Watch real-time connections
sudo journalctl -u endlessh -f

# Count trapped IPs
sudo journalctl -u endlessh | grep "ACCEPT" | awk '{print $NF}' | sort | uniq -c | sort -rn

# View connection duration
sudo journalctl -u endlessh | grep "CLOSE"
```

---

### IDS (Suricata)

**Installation:**
```bash
# Install as IDS (passive monitoring)
ansible-playbook playbooks/liaison_main.yml -e tool=ids -e ids_type=IDS

# Install as IPS (inline blocking)
ansible-playbook playbooks/liaison_main.yml -e tool=ids -e ids_type=IPS
```

**Manage Suricata Service:**
```bash
# Start Suricata
sudo systemctl start suricata

# Stop Suricata
sudo systemctl stop suricata

# Restart Suricata
sudo systemctl restart suricata

# Check status
sudo systemctl status suricata

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
```

**Update Rules:**
```bash
# Update Suricata rules
sudo suricata-update

# Update and restart
sudo suricata-update && sudo systemctl restart suricata

# List enabled rule sources
sudo suricata-update list-sources

# Enable a rule source
sudo suricata-update enable-source et/open
```

**View Logs and Alerts:**
```bash
# View fast.log (alerts)
sudo tail -f /var/log/suricata/fast.log

# View eve.json (detailed JSON logs)
sudo tail -f /var/log/suricata/eve.json

# Parse eve.json for alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# View stats
sudo cat /var/log/suricata/stats.log
```

---

### Rootkit Scanner

**Installation:**
```bash
# Install rkhunter and chkrootkit
ansible-playbook playbooks/liaison_main.yml -e tool=rootkit -e rootkit_action=install
```

**Run Scan (Full System):**
```bash
# Scan entire filesystem (default)
ansible-playbook playbooks/liaison_main.yml -e tool=rootkit -e rootkit_action=scan
```

**Run Scan (Custom Directory):**
```bash
# Scan specific directory
ansible-playbook playbooks/liaison_main.yml -e tool=rootkit -e rootkit_action=scan -e rootkit_scan_dir=/home

# Scan /etc only
ansible-playbook playbooks/liaison_main.yml -e tool=rootkit -e rootkit_action=scan -e rootkit_scan_dir=/etc
```

**Update Databases:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=rootkit -e rootkit_action=update
```

**Manual rkhunter Commands:**
```bash
# Run full scan
sudo rkhunter --check

# Run scan with no prompts
sudo rkhunter --check --skip-keypress

# Show warnings only
sudo rkhunter --check --report-warnings-only

# Update database
sudo rkhunter --update

# Update file properties database
sudo rkhunter --propupd

# View log
cat /var/log/liaison/rootkit/rkhunter-*.log
```

**Manual chkrootkit Commands:**
```bash
# Run full scan
sudo chkrootkit

# Scan specific directory
sudo chkrootkit -r /home

# Quiet mode (infected only)
sudo chkrootkit -q

# Expert mode (more details)
sudo chkrootkit -x

# View log
cat /var/log/liaison/rootkit/chkrootkit-*.log
```

**View Scan Results:**
```bash
# List all rootkit scan logs
ls -la /var/log/liaison/rootkit/

# View latest rkhunter log
cat /var/log/liaison/rootkit/rkhunter-$(date +%Y-%m-%d).log

# View latest chkrootkit log
cat /var/log/liaison/rootkit/chkrootkit-$(date +%Y-%m-%d).log

# Search for warnings in rkhunter logs
grep -i "warning" /var/log/liaison/rootkit/rkhunter-*.log

# Search for infections in chkrootkit logs
grep -i "infected" /var/log/liaison/rootkit/chkrootkit-*.log
```

**Manage Scheduled Scans:**
```bash
# View cron jobs
crontab -l | grep -E "rkhunter|chkrootkit"

# Remove scheduled scans
crontab -l | grep -v "rkhunter\|chkrootkit" | crontab -
```

---

## System Tools

### NTP (Chrony) - Hub-and-Spoke Architecture

> **Resilience:** Master server (172.20.242.104) becomes Stratum 10 Orphan when internet is cut, ensuring all clients continue to sync time even during Red Team attacks.

**Architecture:**
- **Master:** Ubuntu Ecom (172.20.242.104) — Syncs to internet when available, becomes authoritative when disconnected
- **Clients:** All other Linux hosts — Sync ONLY to Master (no public pool dependency)

**Deploy Entire NTP Infrastructure:**
```bash
# Configure both Master and all Clients
ansible-playbook playbooks/liaison_main.yml -e tool=ntp -K
```

**Deploy Master Only:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=ntp --limit ntp_servers -K
```

**Deploy Clients Only:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=ntp --limit ntp_clients -K
```

**Remove NTP Configuration:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=ntp -e ntp_action=remove -K
```

**Manage Chrony Service:**
```bash
# Start Chrony (Debian: chrony, RedHat: chronyd)
sudo systemctl start chrony      # Debian/Ubuntu
sudo systemctl start chronyd     # Fedora/Oracle Linux

# Stop Chrony
sudo systemctl stop chrony

# Restart Chrony
sudo systemctl restart chrony

# Check status
sudo systemctl status chrony
```

**Verify Master Configuration:**
```bash
# Check upstream sources (should show pool.ntp.org when internet available)
chronyc sources -v

# Check if Orphan Mode is active (Stratum 10 when disconnected)
chronyc tracking

# View connected clients
chronyc clients
```

**Verify Client Configuration:**
```bash
# Should show ONLY 172.20.242.104 as source
chronyc sources

# Check sync status (Reference ID should be Master's IP)
chronyc tracking | grep "Reference ID"
```

**Force Immediate Time Sync:**
```bash
# Step clock immediately (useful after boot or long disconnect)
sudo chronyc makestep

# Check sync status
chronyc tracking
```

**Configuration Files:**
```bash
# Master config
sudo cat /etc/chrony/chrony.conf
# Key settings: local stratum 10 orphan, allow 172.20.0.0/16

# Client config
sudo cat /etc/chrony/chrony.conf
# Key setting: server 172.20.242.104 iburst prefer
```

**Switching Master/Client Roles (Interactive Script):**
```bash
# Run the NTP Manager interactive menu
chmod +x scripts/ntp_manager.sh
./scripts/ntp_manager.sh
```

Menu options:
1. Show current NTP configuration
2. Change NTP Master (updates inventory.ini + group_vars/all.yml)
3. Deploy NTP (run playbook)
4. Show runtime override commands
5. Exit

**Runtime Override (No File Changes):**
```bash
# Temporarily make Splunk the Master (one-time, not persistent)
ansible-playbook playbooks/liaison_main.yml -e tool=ntp \
  -e ntp_master_ip=172.20.242.20 \
  --limit splunk,fedora_webmail,ubuntu_ecom -K

# Temporarily make Fedora the Master
ansible-playbook playbooks/liaison_main.yml -e tool=ntp \
  -e ntp_master_ip=172.20.242.101 \
  --limit splunk,fedora_webmail,ubuntu_ecom -K
```

**Manual Role Switch (Edit Files):**
1. Edit `inventory/inventory.ini` — Move hosts between `[ntp_servers]` and `[ntp_clients]`
2. Update `group_vars/all.yml` — Set `ntp_master_ip` to new Master's IP
3. Re-run playbook: `ansible-playbook playbooks/liaison_main.yml -e tool=ntp -K`

**View Logs:**
```bash
# Chrony logs
sudo tail -f /var/log/chrony/tracking.log

# Ansible verification log
cat /var/log/liaison/ntp_verify.log
```

---

### PowerShell

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=powershell -l localhost
```

**Start PowerShell:**
```bash
# Start PowerShell
pwsh

# Run single command
pwsh -Command "Get-Process"

# Run script file
pwsh -File script.ps1
```

---

### System Enumeration

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=system
```

**View Enumeration Reports:**
```bash
# Reports are saved to liaison log directory
ls -la /var/log/liaison/enum/

# View latest report
cat /var/log/liaison/enum/report-*.txt
```

---

## System Hardening

### Firewall (iptables)

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=firewall
```

**Features:**
- Default policy: DROP incoming, ACCEPT outgoing
- Allows established/related connections
- Explicitly allows SSH (port 22)
- Allows ports defined in `allowed_ports` variable

**View Rules:**
```bash
# List all rules
sudo iptables -L -n -v

# List rules with line numbers
sudo iptables -L --line-numbers
```

**Add/Remove Rules Manually:**
```bash
# Allow a new port
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Remove a rule by line number
sudo iptables -D INPUT <line_number>

# Save rules (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4

# Save rules (RedHat/Fedora)
sudo iptables-save > /etc/sysconfig/iptables
```

**Configuration:**
- Modify `allowed_ports` in `group_vars/all.yml` to add more ports.
- Set `firewall_flush_existing: true` to clear existing rules before applying.

---

### XRDP Server (Remote Desktop)

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=xrdp
```

**Manage XRDP Service:**
```bash
# Start XRDP
sudo systemctl start xrdp

# Stop XRDP
sudo systemctl stop xrdp

# Check status
sudo systemctl status xrdp

# View logs
sudo journalctl -u xrdp -f
```

**Connect from Windows:**
1. Open Remote Desktop Connection (`mstsc.exe`)
2. Enter server IP address (e.g., `172.20.242.104`)
3. Connect and login with Linux credentials

**Troubleshooting:**
```bash
# Check if port 3389 is listening
sudo ss -tlnp | grep 3389

# Verify .xsession exists
cat ~/.xsession
```

---

### ClamAV Antivirus

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=clamav
```

**Manage ClamAV Service:**
```bash
# Check daemon status (Debian/Ubuntu)
sudo systemctl status clamav-daemon

# Check daemon status (RedHat/Fedora)
sudo systemctl status clamd@scan

# Update definitions manually
sudo freshclam
```

**Manual Scanning:**
```bash
# Scan a directory
clamscan -r /home

# Scan with infected file removal (DANGER!)
clamscan -r --remove /path/to/scan

# Scan and move infected to quarantine
clamscan -r --move=/var/quarantine /path/to/scan
```

**View Scan Logs:**
```bash
cat /var/log/clamav/manual_scan.log
```

**Cron Job:**
- Runs daily at 3:00 AM
- Scans directory defined in `clamav_scan_dir` (default: `/home`)
- Logs to `clamav_log_file` (default: `/var/log/clamav/manual_scan.log`)

---

### Backup & Restore

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=backup
```

**Run Backup Manually:**
```bash
sudo /usr/local/bin/backup.sh
```

**View Backups:**
```bash
ls -la /var/backups/liaison/
```

**Restore from Backup:**
```bash
# Extract backup
cd /
sudo tar -xzf /var/backups/liaison/backup_YYYYMMDD_HHMMSS.tar.gz
```

**What Gets Backed Up:**
- `/etc` - System configuration
- `/var/www` - Web files (if exists)
- `/home` - User home directories
- `/var/lib/mysql` - MySQL data (if exists)

**Cron Job:**
- Runs daily at 2:00 AM
- Logs to `/var/log/backup.log`

---

### User Audit

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=audit
```

**What It Checks:**
- Users with UID 0 (root-level privileges)
- Users with empty passwords in `/etc/shadow`

**Manual Audit Commands:**
```bash
# Find UID 0 users
awk -F: '($3 == 0) {print $1}' /etc/passwd

# Find users with empty passwords
sudo awk -F: '($2 == "" ) {print $1}' /etc/shadow

# Find users with no password required
sudo awk -F: '($2 == "!" || $2 == "*") {print $1}' /etc/shadow

# List sudoers
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
```

---

### Extended Docker Services

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=docker
```

**Available Services:**
| Service | Image | Port | Description |
|---------|-------|------|-------------|
| Filebrowser | filebrowser/filebrowser | 8080 | Web-based file manager |
| ownCloud | owncloud/server | 8081 | Private cloud storage |
| TFTP | pghalliday/tftp | 69/udp | Simple file transfer |

**Start Specific Service:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=docker -e service_key=filebrowser
```

**Access Services:**
- Filebrowser: `http://<server_ip>:8080`
- ownCloud: `http://<server_ip>:8081`

---

## Removal & Uninstall

All removal commands use the same `liaison_main.yml` playbook with `_action=remove` flags.

> [!IMPORTANT]
> If your user requires a sudo password, add the `-K` flag to any command below.

### VPN Removal
```bash
# Remove WireGuard
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=remove -e vpn_type=wireguard

# Remove OpenVPN
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=remove -e vpn_type=openvpn

# Remove SoftEther (use -K if password required)
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=remove -e vpn_type=softether -K
```

### Tool Removal
```bash
# Remove Docker engine
ansible-playbook playbooks/liaison_main.yml -e tool=docker -e docker_action=remove

# Remove Chrony (NTP)
ansible-playbook playbooks/liaison_main.yml -e tool=ntp -e ntp_action=remove

# Remove PowerShell
ansible-playbook playbooks/liaison_main.yml -e tool=powershell -e powershell_action=remove

# Remove Honeypot (Endlessh)
ansible-playbook playbooks/liaison_main.yml -e tool=honeypot -e honeypot_action=remove

# Remove IDS (Suricata)
ansible-playbook playbooks/liaison_main.yml -e tool=ids -e ids_action=remove
```

---

## Quick Reference

### Service Management (systemctl)
```bash
sudo systemctl start <service>
sudo systemctl stop <service>
sudo systemctl restart <service>
sudo systemctl status <service>
sudo systemctl enable <service>   # Start on boot
sudo systemctl disable <service>  # Don't start on boot
sudo journalctl -u <service> -f   # View logs
```

### Common Log Locations
| Service | Log Location |
|---------|--------------|
| Liaison | `/var/log/liaison/` |
| WireGuard | `journalctl -u wg-quick@wg0` |
| OpenVPN | `/var/log/openvpn/` |
| SoftEther | `/opt/vpnserver/server_log/` |
| Suricata | `/var/log/suricata/` |
| Endlessh | `journalctl -u endlessh` |
| Chrony | `journalctl -u chrony` |
| Docker | `journalctl -u docker` |

### Firewall Quick Commands
```bash
# iptables
sudo iptables -L -n -v
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

---

## Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status <service>

# View detailed logs
sudo journalctl -u <service> -n 50 --no-pager

# Check config syntax (service-specific)
sudo suricata -T -c /etc/suricata/suricata.yaml  # Suricata
sudo wg show  # WireGuard
```

### Port Already in Use
```bash
# Find what's using a port
sudo ss -tlnp | grep :<port>
sudo lsof -i :<port>

# Kill process using port
sudo kill $(sudo lsof -t -i:<port>)
```

### Permission Denied
```bash
# Check file permissions
ls -la /path/to/file

# Fix ownership
sudo chown root:root /path/to/file

# Fix permissions
sudo chmod 644 /path/to/file  # rw-r--r--
sudo chmod 755 /path/to/dir   # rwxr-xr-x
```

### Network Connectivity
```bash
# Test connectivity
ping -c 4 8.8.8.8

# Check DNS
nslookup google.com

# Check routes
ip route

# Check firewall
sudo iptables -L -n
```
