# liaison-ansible-mwccdc

## Quick start
Run commands from the repo root so `ansible.cfg` is picked up (roles_path + inventory). If you must run elsewhere, set `ANSIBLE_CONFIG=/path/to/ansible.cfg`.

> 📖 **New to the services?** See [SERVICE_GUIDE.md](SERVICE_GUIDE.md) for post-installation usage instructions for all tools.

1) Run the setup script to install Ansible and collections:
   ```bash
   chmod +x setup.sh && ./setup.sh
   ```
   Or manually install collections:
   ```bash
   ansible-galaxy collection install ansible.posix community.general community.docker
   ```
2) Inventory defaults via ansible.cfg to `inventory/inventory.ini` (no `-i` needed unless overriding).
3) Set vars:
   - Non-secret defaults: `group_vars/all.yml`
   - Secrets: `group_vars/vault.yml` (plaintext until you `ansible-vault encrypt group_vars/vault.yml`)
4) Run tools headless via `-e tool=...`; defaults to prompt if omitted.

Examples (VPN + non-VPN):
```bash
# WireGuard install
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=install -e vpn_type=wireguard

# OpenVPN install
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=install -e vpn_type=openvpn

# SoftEther install (provide password)
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=install -e vpn_type=softether -e softether_server_password=REDACTED

# Remove any VPN stack
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_action=remove

# Run everything
ansible-playbook playbooks/liaison_main.yml -e tool=all

# Docker engine install
ansible-playbook playbooks/liaison_main.yml -e tool=docker

# Dockerize selected service (service_key from group_vars/all.yml)
ansible-playbook playbooks/liaison_main.yml -e tool=docker -e service_key=vpn

# Subnet sweep (ping scan)
ansible-playbook playbooks/liaison_main.yml -e tool=subnet -e subnet_cidr=192.168.1.0/24

# Nmap scan (mode via nmap_type)
ansible-playbook playbooks/liaison_main.yml -e tool=nmap -e nmap_type=aggressive -e nmap_target=10.0.0.0/24

# FIM monitor (fim_choice: 1 monitor, 2 list, 3 stop, 4 view)
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=1

# NTP chrony configure (hosts must be in ntp_servers/ntp_clients groups)
ansible-playbook playbooks/liaison_main.yml -e tool=ntp

# PowerShell install (Ubuntu/Debian; local host only)
ansible-playbook playbooks/liaison_main.yml -e tool=powershell -l localhost

# TShark capture/read/filter
ansible-playbook playbooks/liaison_main.yml -e tool=tshark -e tshark_action=capture

# System enumeration
ansible-playbook playbooks/liaison_main.yml -e tool=system

# Honeypot (Endlessh)
ansible-playbook playbooks/liaison_main.yml -e tool=honeypot

# IDS (Suricata)
ansible-playbook playbooks/liaison_main.yml -e tool=ids

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

## Inventory
`inventory/inventory.ini` ships with:
- `liaison_local`: localhost (for local tools)
- `vpn_servers`: 172.20.242.104
- `ntp_servers`: 172.20.242.104
- `ntp_clients`: 172.20.242.105
- `all:vars`: `ansible_user`, SSH key path

Adjust hosts/IPs as needed; keep group names consistent with playbooks.

## Vars and secrets
- `group_vars/all.yml`: non-sensitive defaults (ports, nets, service vars).
- `group_vars/vault.yml`: place secrets like `softether_server_password`; encrypt with:
  ```bash
  ansible-vault encrypt group_vars/vault.yml
  ```
  To run with vault:
   ```bash
   ansible-playbook playbooks/liaison_main.yml --ask-vault-pass -e tool=vpn -e vpn_type=softether
   ```

## Tool matrix (set `-e tool=...`)
- `vpn`: role `vpn_manager` (install/remove: WireGuard/OpenVPN/SoftEther)
- `docker`: `docker_install`, `docker_services`
- `subnet`: `subnet_ping`
- `nmap`: `nmap_scanner`
- `fim`: `fim_monitor`
- `ntp`: `ntp_broadcast`
- `powershell`: `powershell_install`
- `tshark`: `tshark_tools`
- `system`: `system_enum`
- `honeypot`: `honeypot_manager`
- `ids`: `ids_manager`
- `firewall`: `firewall_hardening` (iptables-based)
- `xrdp`: `xrdp_server` (XFCE4 desktop)
- `clamav`: `clamav_antivirus`
- `backup`: `backup_restore`
- `audit`: `user_audit`
- `all`: runs everything above

New tool notes:
- Firewall: iptables with default deny policy; add ports via `allowed_ports` in `group_vars/all.yml`.
- XRDP: Installs XRDP + XFCE4; connect via Windows RDP to port 3389.
- ClamAV: Installs daemon, updates definitions, schedules daily scan at 3 AM.
- Backup: Creates backup script and cron job (2 AM); backs up `/etc`, `/home`, `/var/www`.
- Audit: Reports UID 0 users and empty passwords in Ansible output.

Non-VPN notes:
- Docker: installs engine then dockerizes selected service from `docker_services` list; set `service_key` (default vpn) and `docker_action=remove` to uninstall engine and prune `/var/lib/docker`.
- Subnet: `nmap -sn` sweep; requires nmap on target.
- Nmap: modes via `nmap_type` (port/service/os/vuln/aggressive/sn) and `nmap_target`.
- FIM: `fim_choice` controls action; baseline/logs stored under `/tmp/fim_sessions`.
- NTP: chrony Hub-and-Spoke architecture; uses `ntp_servers`/`ntp_clients` groups; **use `scripts/ntp_manager.sh` to switch Master**; set `ntp_action=remove` to uninstall.
- PowerShell: Ubuntu/Debian path; set `powershell_action=remove` for uninstall.
- TShark: capture/read/filter; requires tshark package present.
- System: writes enum report under `{{ liaison_log_dir }}/enum`.
- Honeypot: installs Endlessh, templates config/service, logs can be exported; set `honeypot_action=remove` to stop/uninstall.
- IDS: installs Suricata, templates config/rules; IPS toggle via `ids_type`; set `ids_action=remove` to stop/uninstall.

## VPN knobs (extra-vars)
- `vpn_action`: `install` | `remove` (default: install)
- `vpn_type`: `wireguard` | `openvpn` | `softether` (default: wireguard)
- Common vars in `group_vars/all.yml`: `openvpn_port`, `openvpn_proto`, `wg_listen_port`, `wg_client_ips`, etc.

## Logging
- Runs append to `{{ liaison_log_dir }}/summary.log` (default `/var/log/liaison`). Ensure writable by Ansible user.

## Offline tips
- Pre-download Galaxy collections (`ansible-galaxy collection download ...`) and pip wheels if needed.
- Keep templates local (role copies of OpenVPN/WG configs are bundled under `roles/vpn_manager/templates`).
- Packages auto-installed by roles: `nmap` (nmap_scanner, subnet_ping), `tshark` (tshark_tools), `chrony` (ntp_broadcast), `docker` (docker_install), `powershell` (Ubuntu/Debian only).

## Troubleshooting
- Facts: `gather_facts` is on; if slow, set `-e ansible_facts_modules=setup` or use `-t` limits.
- Firewall: UFW rules gated by `ufw_enabled`. Set false to skip.
- Privilege: ensure `become` works (sudo/root). For key auth, confirm `ansible_ssh_private_key_file` is valid.

## Standalone VPN Playbooks

The standalone `vpn_install.yml` and `vpn_removal.yml` playbooks are available as direct alternatives to the main toolkit:

```bash
# Install SoftEther directly (use -K if sudo password required)
ansible-playbook playbooks/vpn_install.yml -e vpn_type=softether -l localhost -K

# Remove SoftEther directly (use -K if sudo password required)
ansible-playbook playbooks/vpn_removal.yml -e vpn_type=softether -l localhost -K
```

> **Note:** If your user requires a sudo password, always use the `-K` flag to avoid timeout errors during long-running tasks like SoftEther compilation.
