# CCDC Test Scripts - Quick Reference Guide

Automated setup and response tooling for MWCCDC-style ranges. Every script ships ready for Debian/Ubuntu and Fedora/RHEL hosts and assumes competition VMs with `sudo` access.

## Compliance Reminder
- Each script now pauses on launch with a TeamPack compliance prompt. Type `YES` to confirm you are working only on team-owned hosts.
- Most scripts require root; run with `sudo ./script.sh` unless otherwise noted.

## Script Quick Reference

| Script | Focus | Quick Run | Highlights |
|--------|-------|-----------|------------|
| `install_vpns_2.sh` | Multi-VPN server automation | `sudo ./install_vpns_2.sh [--quick|--openvpn|--wireguard|--softether|--all]` | Installs/removes OpenVPN, WireGuard, SoftEther with backups, NAT prep, diagnostics, and credential export |
| `vpn_client_connect_2.sh` | VPN client onboarding | `sudo ./vpn_client_connect_2.sh` | Builds OpenVPN/WireGuard/SoftEther clients, runs TCP/UDP reachability tests, bundles secure file-transfer helpers |
| `FIM.sh` | File integrity monitoring | `sudo ./FIM.sh` | Multiple concurrent watchers with SHA256 baselines, live log tailing, graceful cleanup |
| `Docker_install.sh` | Docker engine lifecycle | `sudo ./Docker_install.sh` | Adds official repos, installs or purges Docker CE stack, groups users, prints CCDC usage primer |
| `docker_service_manager.sh` | Containerize team services | `sudo ./docker_service_manager.sh` | Detects eight security services, backs up configs, dockerizes via run or Compose with security flags |
| `InstallPowerShell.sh` | PowerShell for Linux | `sudo ./InstallPowerShell.sh` | Adds Microsoft feed, installs/ verifies/uninstalls `pwsh`, offers interactive launch |
| `IDS.sh` | Suricata IDS/IPS | `sudo ./IDS.sh` | Guided install/uninstall, mode and interface selection, service tuning |
| `Honeypot.sh` | Endlessh tarpit | `sudo ./Honeypot.sh` | Deploys or removes Endlessh, adjusts service settings, exports incident logs |
| `SubnetAndPingConfigs.sh` | Subnetting & ICMP validation | `sudo ./SubnetAndPingConfigs.sh` | IPv4/IPv6 subnet calculators, temporary interface config, firewall ICMP rules, cleanup paths |
| `File_Transfer_Server4.sh` | FTP/SFTP/TFTP servers | `sudo ./File_Transfer_Server4.sh` | Installs or removes individual services, provisions users, stores credentials, provides view/export utility |
| `file_transfer_client2.sh` | File transfer client | `./file_transfer_client2.sh` | Menu workflows for FTP/SFTP/TFTP, auto-imports creds, built-in connectivity tests, interactive sessions |
| `Network_Scanner_Tshark.sh` | Live capture tooling | `sudo ./Network_Scanner_Tshark.sh` | Interface discovery, capture/save/read filters, credential extraction, custom command runner |
| `PCAP_Analyzer_Tshark.sh` | Saved PCAP analytics | `sudo ./PCAP_Analyzer_Tshark.sh` | Guided filter library (DNS/HTTP/ports/SYN), exports summaries, incident-response friendly |
| `system_enumerator.sh` | Host baseline & reporting | `sudo ./system_enumerator.sh` | Category-based enumeration with summary counts, rootkit checks, report saved to `/root/enum_report.txt` |
| `Network_Scanner_Nmap.sh` | Nmap reconnaissance | `sudo ./Network_Scanner_Nmap.sh` | Installs Nmap if absent, 10-option scan menu, progress spinner, logs in `/var/log/nmap_logs/` |

---

## VPN & Connectivity

**`install_vpns_2.sh`**
- Supports CLI flags for unattended installs (`--quick`, `--all`, module-specific flags).
- Creates `/backup/vpn_*` snapshots, fixes package-manager locks, hardens NAT/firewall rules, and runs diagnostics.
- Menu also surfaces certificate management guidance and integration checklists for Palo Alto NAT.

**`vpn_client_connect_2.sh`**
- Installs tooling (OpenVPN, WireGuard, SoftEther client dependencies) and validates IPs/ports with TCP or UDP netcat probes.
- Generates WireGuard key material, scrubs known-host entries on SoftEther rebuilds, and bundles rsync/scp helpers for post-tunnel file movement.
- Keeps a log at `/var/log/vpn_client.log` for after-action reviews.

**Quick start**
```bash
# Server
sudo ./install_vpns_2.sh --openvpn

# Client
sudo ./vpn_client_connect_2.sh
# 1) OpenVPN Client Setup → provide cert bundle → follow connect steps
```

---

## Security Monitoring & Deception

**`FIM.sh`**
- Launches background watchers with SHA256 baselines and per-session state in `/tmp/fim_sessions`.
- Blocks duplicate paths, offers live `tail -f` view, and cleans dead sessions automatically.

**`IDS.sh`**
- Installs or removes Suricata, toggles IDS/IPS (NFQUEUE) modes, and exposes service-management utilities.

**`Honeypot.sh`**
- Deploys Endlessh, allows port/service edits, exports tarpit logs for incident response, or removes cleanly.

---

## Infrastructure & Automation

**`Docker_install.sh`**
- Installs Docker CE/CLI/Buildx/Compose plugins from the official repositories with progress spinners and verification.
- Removes legacy packages, adds the invoking user to the `docker` group, and prints MWCCDC-specific Docker usage notes.

**`docker_service_manager.sh`**
- Detects host services (e.g., Suricata, vsftpd, OpenVPN, Cowrie) and offers to dockerize them with backups and hardened run options (`no-new-privileges`, read-only filesystems, capability controls).
- Generates Compose files on demand, tails logs, and can stop all managed containers in one action.

**`InstallPowerShell.sh`**
- Adds Microsoft repositories for apt/dnf/yum, installs PowerShell, verifies the install, offers to launch or uninstall, and prints cross-platform cheat sheets.

**`SubnetAndPingConfigs.sh`**
- Provides IPv4/IPv6 subnet calculators, temporary interface configuration, firewall rule toggles (UFW or firewalld), and teardown routines.

---

## File Transfer Tooling

**`File_Transfer_Server4.sh`**
- Handles install/remove/view for FTP (vsftpd), SFTP (OpenSSH chroot), and TFTP, provisioning users and storing credentials securely in `/etc/fts_credentials.conf`.
- View mode shows IP/port, current status, and can base64-export credentials for quick client setup.

**`file_transfer_client2.sh`**
- Detects required client binaries, imports stored credentials automatically, performs network reachability checks, and supports upload/download/list/interactive workflows for each protocol.
- Maintains connection state so teams can pivot between protocols without re-entering details.

---

## Network Visibility & Analysis

**`Network_Scanner_Tshark.sh`**
- Offers live capture, PCAP output, credential extraction, TCP conversation stats, and custom command entry with saved logs under `/tmp/tshark_logs`.

**`PCAP_Analyzer_Tshark.sh`**
- Reads stored captures and applies ready-made filters (HTTP, DNS, SYN/ACK, conversations, credential hunts) with optional export of filtered results.

**`Network_Scanner_Nmap.sh`**
- Presents 10 curated scan modes, installs Nmap automatically, and logs results with timestamps; summary output highlights open ports and discoveries.

---

## Host Baselines & Reporting

**`system_enumerator.sh`**
- Category-driven enumeration (system, users, network, processes, logs, filesystem, security) with counts for SUID files and hidden artifacts.
- Runs optional rootkit scanners, captures cron jobs, packages, firewall states, and writes a master report to `/root/enum_report.txt`.

---

## Suggested Run Order (Competition Prep)
- Infrastructure first: `Docker_install.sh`, `docker_service_manager.sh`, `InstallPowerShell.sh`, `SubnetAndPingConfigs.sh`.
- Defensive stack: `IDS.sh`, `Honeypot.sh`, `FIM.sh`.
- Services and access: `File_Transfer_Server4.sh`, `install_vpns_2.sh`, `vpn_client_connect_2.sh`.
- Monitoring and hunting: `Network_Scanner_Tshark.sh`, `Network_Scanner_Nmap.sh`, `PCAP_Analyzer_Tshark.sh`, `system_enumerator.sh`.

---

## Troubleshooting Cheatsheet
- Missing privileges → rerun with `sudo` and ensure TeamPack prompt is acknowledged.
- Package installation errors → check network access or rerun `apt update`/`dnf makecache`.
- Service startups → inspect `journalctl -u <service>` or the script-specific log paths noted above.
- Port collisions → verify active listeners with `ss -tulpen` before redeploying.

Logs worth bookmarking:
- VPN server installs: `/var/log/vpn_install.log`
- VPN client runs: `/var/log/vpn_client.log`
- Nmap scans: `/var/log/nmap_logs/`
- TShark captures: `/tmp/tshark_logs/`
- File transfer credentials: `/etc/fts_credentials.conf`
- System enumeration: `/root/enum_report.txt`

---

## Competition Reminders
- Document IPs, ports, and credentials as services come online—especially for Palo Alto NAT updates.
- Rotate keys/passwords immediately after scripted installs.
- Keep backups of generated configs (`/backup`, Docker backups, credential files) off-box where possible.
- Review script change logs regularly; the repository reflects 2025 updates across all automation.

Need deeper detail? Launch any script with the default menu and browse its help/diagnostic options.