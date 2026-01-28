# CCDC-Development Vagrant Environment

Multi-OS test environment for CCDC script development and testing.

## Quick Start

```bash
# Start all Linux VMs (Ubuntu, Fedora, Oracle, Rocky, Debian)
vagrant up

# Start specific VM
vagrant up ubuntu

# Start Windows VMs (resource-intensive)
vagrant up win11 winserver2019 winserver2022

# Start VyOS router
vagrant up vyos

# SSH into Linux VM
vagrant ssh ubuntu

# Destroy all VMs
vagrant destroy -f
```

## VMs Included

### Linux (192.168.56.10-19)

| Name | Box | IP | OS Family | Autostart |
|------|-----|----|-----------| --------- |
| ubuntu | bento/ubuntu-24.04 | 192.168.56.10 | Debian | Yes |
| fedora | bento/fedora-42 | 192.168.56.11 | RedHat | Yes |
| oracle | bento/oracle-9 | 192.168.56.12 | RedHat | Yes |
| rocky | bento/rockylinux-9 | 192.168.56.13 | RedHat | Yes |
| debian | bento/debian-12 | 192.168.56.14 | Debian | Yes |

### Windows (192.168.56.20-29)

| Name | Box | IP | Autostart |
|------|-----|----| --------- |
| win11 | gusztavvargadr/windows-11 | 192.168.56.20 | No |
| winserver2019 | gusztavvargadr/windows-server-2019-standard | 192.168.56.21 | No |
| winserver2022 | gusztavvargadr/windows-server-2022-standard | 192.168.56.22 | No |

### Network Appliances (192.168.56.1-9)

| Name | Box | IP | Autostart |
|------|-----|----| --------- |
| vyos | vyos/current | 192.168.56.1 | No |

## Default Credentials

| System | Username | Password |
|--------|----------|----------|
| Linux VMs | testuser | Changeme1! |
| Linux VMs | vagrant | vagrant |
| Windows VMs | testuser | Changeme1! |
| Windows VMs | vagrant | vagrant |
| VyOS | vyos | vyos |

## Script Testing

The parent directory (`../`) is synced to `/vagrant/` on all Linux VMs. This allows direct testing of scripts:

```bash
# SSH into VM
vagrant ssh ubuntu

# Run a script
sudo bash /vagrant/LinuxDev/SomeScript.sh

# Or copy and run
cp /vagrant/LinuxDev/SomeScript.sh /tmp/
chmod +x /tmp/SomeScript.sh
sudo /tmp/SomeScript.sh
```

For Windows, use WinRM or RDP:

```bash
# Connect via WinRM (PowerShell)
vagrant winrm win11

# RDP (requires vagrant-rdp plugin)
vagrant rdp win11
```

## Resource Requirements

| Configuration | VMs | RAM Required | Disk |
|---------------|-----|--------------|------|
| Linux only | 5 | ~6 GB | ~25 GB |
| Linux + VyOS | 6 | ~6.5 GB | ~26 GB |
| Full (Linux + Windows) | 9 | ~20 GB | ~80 GB |

## Unsupported Platforms

### Palo Alto VM-Series

Not supported on VirtualBox. Requires VMware ESXi/Workstation or KVM.

### Cisco FTDv

Not supported on VirtualBox. Requires VMware ESXi or KVM.

For these appliances, consider using GNS3, EVE-NG, or Cisco CML/VIRL.

## Troubleshooting

### Box Download Failures

If a box download fails, try:

```bash
vagrant box add bento/ubuntu-24.04 --provider virtualbox
```

### Windows Boot Timeout

Windows VMs take longer to boot. If timeout occurs:

```bash
vagrant up win11 --provision
```

### VyOS Issues

The `vyos/current` box may need updating. Alternative:

```bash
# Download manually from VyOS website and add
vagrant box add vyos-custom /path/to/vyos.box
```

Then update Vagrantfile to use `vyos-custom`.
