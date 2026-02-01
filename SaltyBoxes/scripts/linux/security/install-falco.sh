#!/bin/bash
# =============================================================================
# FALCO QUICK DEPLOY - CCDC EDITION
# =============================================================================
# Rapid Falco deployment for competition environments
# Logs to /var/log/falco/falco_alerts.log for Splunk integration
# =============================================================================

set -e

echo "=========================================="
echo "  FALCO QUICK DEPLOY - CCDC"
echo "=========================================="

# Detect OS
if [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="redhat"
else
    echo "Unsupported OS"
    exit 1
fi

echo "[*] Detected OS family: $OS_FAMILY"

# Install Falco
if [ "$OS_FAMILY" = "debian" ]; then
    echo "[*] Adding Falco repository (Debian/Ubuntu)..."
    # Remove old keyring if exists to avoid gpg errors
    rm -f /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq falco
else
    echo "[*] Adding Falco repository (RHEL/Rocky)..."
    cat > /etc/yum.repos.d/falcosecurity.repo << 'EOF'
[falcosecurity]
name=Falco Security
baseurl=https://download.falco.org/packages/rpm
gpgcheck=1
gpgkey=https://falco.org/repo/falcosecurity-packages.asc
enabled=1
EOF
    yum install -y -q falco || dnf install -y -q falco
fi

# Create log directory
mkdir -p /var/log/falco
chmod 755 /var/log/falco

# Enable BPF if restricted (common in VMs and containers)
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    BPF_STATUS=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    if [ "$BPF_STATUS" != "0" ]; then
        echo "[*] Enabling BPF access for Falco..."
        echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
    fi
fi

# Configure Falco for Splunk logging
echo "[*] Configuring Falco for Splunk logging..."
cat > /etc/falco/falco.yaml << 'EOF'
# Falco CCDC Config - uses modern_ebpf engine
engine:
  kind: modern_ebpf
  modern_ebpf:
    cpus_for_each_buffer: 2

# Only load CCDC rules (default rules require container plugin)
rules_files:
  - /etc/falco/rules.d/ccdc_quick.yaml

json_output: true
json_include_output_property: true
json_include_tags_property: true

file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco/falco_alerts.log

stdout_output:
  enabled: true

syslog_output:
  enabled: false

http_output:
  enabled: false

buffered_outputs: false

priority: debug
watch_config_files: false
EOF

# Create log file to ensure proper permissions
touch /var/log/falco/falco_alerts.log
chown root:root /var/log/falco/falco_alerts.log

# Create rules directory
mkdir -p /etc/falco/rules.d

# Deploy CCDC rules (condensed critical rules)
echo "[*] Deploying CCDC detection rules..."
cat > /etc/falco/rules.d/ccdc_quick.yaml << 'RULES'
# CCDC Quick Deploy Rules

- macro: spawned_process
  condition: evt.type in (execve, execveat)

- macro: open_write
  condition: evt.type in (open, openat, openat2) and evt.is_open_write=true

- macro: open_read
  condition: evt.type in (open, openat, openat2) and evt.is_open_read=true

- rule: ROOTKIT - Kernel Module Loaded
  desc: Detect kernel module loading
  condition: evt.type in (init_module, finit_module) or (spawned_process and proc.name in (insmod, modprobe))
  output: "CRITICAL [ROOTKIT] Kernel module loaded (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, rootkit]

- rule: ROOTKIT - LD_PRELOAD Injection
  desc: Detect LD_PRELOAD abuse
  condition: spawned_process and proc.env contains "LD_PRELOAD"
  output: "CRITICAL [ROOTKIT] LD_PRELOAD injection (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, rootkit]

- rule: EBPF - BPF Program Loaded
  desc: Detect BPF loading (BPFDoor indicator)
  condition: evt.type = bpf and not proc.name in (falco, sysdig, cilium, systemd)
  output: "CRITICAL [EBPF] BPF program loaded (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, ebpf, bpfdoor]

- rule: EBPF - Raw Socket Created
  desc: Detect raw socket (BPFDoor indicator)
  condition: evt.type in (socket) and evt.arg.domain = AF_PACKET and not proc.name in (tcpdump, dhclient)
  output: "CRITICAL [EBPF] Raw socket created (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, ebpf, bpfdoor]

- rule: PERSIST - SSH Keys Modified
  desc: Detect authorized_keys changes
  condition: open_write and fd.name contains "authorized_keys"
  output: "CRITICAL [PERSIST] SSH keys modified (user=%user.name file=%fd.name)"
  priority: CRITICAL
  tags: [ccdc, persistence]

- rule: PERSIST - Cron Modified
  desc: Detect cron changes
  condition: open_write and (fd.name startswith /etc/cron or fd.name startswith /var/spool/cron)
  output: "CRITICAL [PERSIST] Cron modified (user=%user.name file=%fd.name)"
  priority: CRITICAL
  tags: [ccdc, persistence]

- rule: PERSIST - Systemd Service Created
  desc: Detect systemd service creation
  condition: open_write and fd.name startswith /etc/systemd/system and fd.name endswith ".service"
  output: "CRITICAL [PERSIST] Systemd service created (user=%user.name file=%fd.name)"
  priority: CRITICAL
  tags: [ccdc, persistence]

- rule: CREDS - Shadow File Access
  desc: Detect /etc/shadow access
  condition: open_read and fd.name = /etc/shadow and not proc.name in (sshd, sudo, su, passwd, login)
  output: "CRITICAL [CREDS] Shadow file accessed (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, credentials]

- rule: C2 - Reverse Shell
  desc: Detect reverse shell
  condition: >
    spawned_process and
    ((proc.name in (nc, ncat, netcat) and (proc.cmdline contains "-e" or proc.cmdline contains "-c")) or
     (proc.name = bash and proc.cmdline contains "/dev/tcp") or
     (proc.name in (python, python3) and proc.cmdline contains "socket"))
  output: "CRITICAL [C2] Reverse shell detected (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, c2]

- rule: C2 - Netcat Listener
  desc: Detect netcat listener
  condition: spawned_process and proc.name in (nc, ncat, netcat) and proc.cmdline contains "-l"
  output: "CRITICAL [C2] Netcat listener (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, c2]

- rule: WEBSHELL - Shell from Web Server
  desc: Detect shell from web process
  condition: spawned_process and proc.pname in (apache2, httpd, nginx, php-fpm, php, java) and proc.name in (bash, sh, python, perl)
  output: "CRITICAL [WEBSHELL] Shell from web server (user=%user.name command=%proc.cmdline parent=%proc.pname)"
  priority: CRITICAL
  tags: [ccdc, webshell]

- rule: EVASION - Log Tampering
  desc: Detect log deletion
  condition: evt.type in (unlink, unlinkat) and evt.arg.name startswith /var/log and not proc.name = logrotate
  output: "CRITICAL [EVASION] Log tampering (user=%user.name file=%evt.arg.name)"
  priority: CRITICAL
  tags: [ccdc, evasion]

- rule: EVASION - History Cleared
  desc: Detect history clearing
  condition: spawned_process and (proc.cmdline contains "history -c" or proc.cmdline contains "HISTFILE=/dev/null")
  output: "CRITICAL [EVASION] History cleared (user=%user.name command=%proc.cmdline)"
  priority: CRITICAL
  tags: [ccdc, evasion]

- rule: BASELINE - Execution from /tmp
  desc: Detect execution from temp dirs
  condition: spawned_process and (proc.exepath startswith /tmp or proc.exepath startswith /dev/shm)
  output: "WARNING [BASELINE] Execution from temp (user=%user.name exe=%proc.exepath)"
  priority: WARNING
  tags: [ccdc, baseline]
RULES

# Start Falco (prefer modern-bpf for best compatibility)
echo "[*] Starting Falco service..."

# Disable other Falco services to avoid conflicts
for svc in falco-bpf.service falco-kmod.service falco.service; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# Enable and start modern-bpf
if systemctl enable falco-modern-bpf 2>/dev/null && systemctl start falco-modern-bpf 2>/dev/null; then
    echo "[OK] Started falco-modern-bpf.service"
else
    echo "[WARN] modern-bpf failed, trying fallback services..."
    for svc in falco-bpf.service falco-kmod.service falco.service; do
        if systemctl start "$svc" 2>/dev/null; then
            echo "[OK] Started $svc"
            break
        fi
    done
fi

# Verify
sleep 2
if pgrep -x falco > /dev/null 2>&1; then
    echo ""
    echo "=========================================="
    echo "  FALCO DEPLOYED SUCCESSFULLY"
    echo "=========================================="
    echo "Log file: /var/log/falco/falco_alerts.log"
    echo ""
    echo "Splunk inputs.conf:"
    echo "[monitor:///var/log/falco/falco_alerts.log]"
    echo "sourcetype = falco"
    echo "index = security"
    echo "=========================================="
else
    echo "[ERROR] Falco failed to start"
    exit 1
fi
