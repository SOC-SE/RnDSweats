# System Administration & Security Scripts

A collection of automated tools for system hardening, monitoring, and network management on Debian/Ubuntu and Fedora/RHEL systems.

## Script List

### Infrastructure
*   **Docker_install.sh**: Installs and configures Docker environment.
*   **docker_service_manager.sh**: Manages containerized services.
*   **InstallPowerShell.sh**: Sets up PowerShell on Linux.
*   **SubnetAndPingConfigs.sh**: Network configuration utilities.

### Networking & VPN
*   **install_vpns_2.sh**: Deploys VPN server solutions.
*   **vpn_client_connect_2.sh**: Configures VPN client connections.

### File Transfer
*   **File_Transfer_Server4.sh**: Sets up file transfer services.
*   **file_transfer_client2.sh**: Client utility for file transfers.

### Security & Monitoring
*   **FIM.sh**: File Integrity Monitoring tool.
*   **IDS.sh**: Intrusion Detection System deployment.
*   **Honeypot.sh**: Deploys deception services.
*   **system_enumerator.sh**: Generates system status reports.

### Analysis
*   **Network_Scanner_Nmap.sh**: Network discovery tool.
*   **Network_Scanner_Tshark.sh**: Live traffic analysis.
*   **PCAP_Analyzer_Tshark.sh**: Packet capture analysis.

## Usage

Most scripts require root privileges.

```bash
chmod +x *.sh
sudo ./<script_name>.sh
```