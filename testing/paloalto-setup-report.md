# Palo Alto VM Setup Report

**Date**: 2026-01-27
**Status**: BLOCKED - Missing Dependencies

## Image Details

- **Source**: `/home/sam/Downloads/PA-VM-KVM-11.0.0.qcow2`
- **Format**: QCOW2 (KVM/QEMU format)
- **Size**: 4.1 GB
- **Version**: PAN-OS 11.0.0

## Setup Attempt Summary

### Environment Check

| Component | Status | Notes |
|-----------|--------|-------|
| VirtualBox | Installed | `/usr/bin/VBoxManage` available |
| KVM Modules | Loaded | `kvm_amd`, `kvm` modules active |
| QEMU Tools | NOT Installed | `qemu-img` required for conversion |
| System | Arch Linux | Package manager: pacman |

### Conversion Path Required

To use the PA-VM image in VirtualBox:

1. **Convert QCOW2 to VDI** (requires qemu-img):
   ```bash
   qemu-img convert -f qcow2 -O vdi \
     /home/sam/Downloads/PA-VM-KVM-11.0.0.qcow2 \
     /home/sam/Downloads/PA-VM.vdi
   ```

2. **Create VirtualBox VM manually**:
   - Name: `paloalto-vm`
   - Type: Linux, Version: Other Linux (64-bit)
   - Memory: 6656 MB (minimum 6.5 GB)
   - CPUs: 2 (minimum)
   - Disk: Use converted VDI file
   - Network: Host-only adapter (192.168.56.x)

3. **Alternative: Use KVM/QEMU directly** (preferred for qcow2):
   ```bash
   qemu-system-x86_64 -enable-kvm -m 6656 -smp 2 \
     -drive file=/home/sam/Downloads/PA-VM-KVM-11.0.0.qcow2,format=qcow2 \
     -net nic -net user,hostfwd=tcp::8443-:443
   ```

## Blockers

1. **Missing qemu-img tool**: Required for QCOW2 to VDI conversion
   - Package needed: `qemu-base` (Arch Linux)
   - Installation command: `sudo pacman -S qemu-base`
   - Status: Cannot install without sudo password

2. **VirtualBox Compatibility Warning**:
   - Palo Alto does NOT officially support VirtualBox
   - May experience performance issues or instability
   - Recommended platforms: VMware ESXi, KVM/QEMU

## Recommendations

### Option A: Install QEMU tools (Preferred)
```bash
# Install qemu-base for qemu-img
sudo pacman -S qemu-base

# Convert image
qemu-img convert -f qcow2 -O vdi \
  /home/sam/Downloads/PA-VM-KVM-11.0.0.qcow2 \
  /home/sam/Downloads/PA-VM.vdi

# Create VBox VM (manual or via VBoxManage)
VBoxManage createvm --name "paloalto" --ostype "Linux_64" --register
VBoxManage modifyvm "paloalto" --memory 6656 --cpus 2
VBoxManage storagectl "paloalto" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "paloalto" --storagectl "SATA" --port 0 --device 0 \
  --type hdd --medium /home/sam/Downloads/PA-VM.vdi
VBoxManage modifyvm "paloalto" --nic1 hostonly --hostonlyadapter1 vboxnet0
```

### Option B: Use KVM/QEMU Directly
If full QEMU is installed later:
```bash
sudo pacman -S qemu-full virt-manager
# Then use virt-manager GUI or qemu-system-x86_64 CLI
```

### Option C: Skip Palo Alto Testing
- Test PaloAlto/ scripts against API documentation only
- Validate syntax and logic without live firewall
- Mark PaloAlto scripts as "untested on live hardware"

## PA-VM Requirements Reference

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| vCPUs | 2 | 4 |
| RAM | 6.5 GB | 8 GB |
| Disk | 60 GB | 100 GB |
| NICs | 2 | 3+ |

## Default Credentials

- **Username**: `admin`
- **Password**: `admin` (requires change on first login)
- **Management Port**: HTTPS (443)

## Next Steps

1. Install `qemu-base` package when sudo access is available
2. Convert QCOW2 to VDI format
3. Create VirtualBox VM with specifications above
4. Boot and complete initial setup (password change)
5. Configure management interface on 192.168.56.x network
6. Test PaloAlto/ scripts against live VM

---

**Conclusion**: Palo Alto VM testing is deferred pending installation of QEMU tools. PaloAlto/ scripts will be included in static analysis but marked as "dynamic testing pending" in the final report.
