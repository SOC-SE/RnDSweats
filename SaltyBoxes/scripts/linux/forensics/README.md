# Salt-GUI Forensic Artifact Collection Suite

A comprehensive forensic artifact collection system for Linux systems using SaltStack. Designed for CCDC (Collegiate Cyber Defense Competition) incident response.

## Overview

This module provides:
- **Parallel artifact collection** from all Linux minions
- **Comprehensive system state capture** (processes, network, persistence, users, logs)
- **Web GUI integration** via SaltGUI API
- **Salt state-based deployment** for reliability
- **Test framework** for validation

## Quick Start

### Via SaltGUI Web Interface

1. Navigate to the Forensics section in SaltGUI
2. Select target minions (or use `*` for all)
3. Click "Start Collection"
4. Monitor progress and download artifacts

### Via Salt Command Line

```bash
# Collect from all minions
salt '*' state.apply linux.forensics

# Collect from specific minion
salt 'webserver-01' state.apply linux.forensics

# Collect with custom timestamp
salt '*' state.apply linux.forensics pillar='{"forensics": {"timestamp": "20260127_150000"}}'
```

### Via SaltGUI API

```bash
# Start collection (synchronous)
curl -X POST http://localhost:3000/api/forensics/collect \
  -H "Content-Type: application/json" \
  -H "Cookie: salt-gui.sid=<session_cookie>" \
  -d '{"targets": "*", "timeout": 900}'

# Start collection (async)
curl -X POST http://localhost:3000/api/forensics/collect \
  -H "Content-Type: application/json" \
  -d '{"targets": ["web-01", "db-01"], "async": true}'

# Check async job status
curl http://localhost:3000/api/forensics/status/<collection_id>
```

## What Gets Collected

### System State (Volatile)
- Running processes (`ps auxwwf`, `pstree`)
- Open files (`lsof`)
- Loaded kernel modules (`lsmod`)
- Mounted filesystems
- Memory usage
- System uptime and load

### Network (Volatile)
- Active connections (`ss -tulpan`)
- IP configuration (`ip addr`, `ip route`)
- ARP table (`ip neigh`)
- Firewall rules (iptables, nftables, firewalld, ufw)
- DNS configuration (`/etc/resolv.conf`, `/etc/hosts`)

### Persistence Mechanisms
- All crontabs (system and user)
- Systemd services (enabled, running, custom)
- Init.d scripts
- RC.local
- AT jobs
- **ld.so.preload** (rootkit indicator)

### User Artifacts
- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Sudoers configuration
- SSH authorized_keys for all users
- SSH known_hosts
- Login history (last, lastb, lastlog)

### Shell Artifacts
- System profiles (`/etc/profile`, `/etc/profile.d/*`)
- User profiles (`.bashrc`, `.profile`, `.zshrc`)
- Shell histories (limited to last 10,000 lines)

### Logs
- Auth logs (`/var/log/auth.log`, `/var/log/secure`)
- Syslog (`/var/log/syslog`, `/var/log/messages`)
- Audit logs (`/var/log/audit/`)
- Application logs (Apache, Nginx, MySQL)
- Journal (last 10,000 entries)
- Fail2ban logs

### Package Information
- Installed packages (dpkg/rpm/apk)
- Package verification (debsums/rpm -Va)

### Suspicious Files
- Hidden files in `/tmp` and `/var/tmp`
- `/dev/shm` contents
- World-writable files in system directories
- SUID/SGID binaries in non-standard locations
- Recently modified system files

## Output Structure

Each collection creates a tarball with the following structure:

```
hostname_forensics_YYYYMMDD_HHMMSS/
├── metadata.json              # Collection metadata
├── system/
│   ├── hostname
│   ├── uname.txt
│   ├── uptime.txt
│   ├── os-release
│   ├── lsmod.txt
│   └── mount.txt
├── processes/
│   ├── ps_aux.txt
│   ├── ps_tree.txt
│   └── lsof.txt
├── network/
│   ├── ss_tulpan.txt
│   ├── ip_addr.txt
│   ├── ip_route.txt
│   ├── iptables.txt
│   ├── hosts
│   └── resolv.conf
├── persistence/
│   ├── cron/
│   │   ├── crontab
│   │   ├── user_crontabs.txt
│   │   ├── cron.d/
│   │   └── cron.daily/
│   ├── systemd/
│   │   ├── services_enabled.txt
│   │   ├── services_running.txt
│   │   └── custom_services/
│   ├── init.d/
│   ├── rc.local
│   └── ld.so.preload
├── users/
│   ├── passwd
│   ├── shadow
│   ├── group
│   ├── sudoers
│   ├── sudoers.d/
│   ├── ssh_keys/
│   ├── last.txt
│   └── lastlog.txt
├── shell/
│   ├── profiles/
│   │   ├── etc_profile
│   │   ├── profile.d/
│   │   └── <user>_.bashrc
│   └── histories/
│       └── <user>_.bash_history
├── logs/
│   ├── auth.log
│   ├── syslog
│   └── audit/
├── packages/
│   ├── installed_packages.txt
│   └── package_verification.txt
└── files/
    ├── tmp_hidden.txt
    ├── dev_shm.txt
    ├── world_writable.txt
    └── suid_nonstandard.txt
```

## Salt Master Configuration

To enable artifact retrieval via `cp.push`, add to `/etc/salt/master.d/forensics.conf`:

```yaml
# Enable file receive from minions
file_recv: True
file_recv_max_size: 500

# Increase timeout for forensics jobs
timeout: 300

# Keep job results longer
keep_jobs: 24

# Artifact storage
forensics_artifact_dir: /srv/forensics/artifacts
```

Restart salt-master after configuration:
```bash
systemctl restart salt-master
```

Create the artifact directory:
```bash
mkdir -p /srv/forensics/artifacts
chmod 700 /srv/forensics/artifacts
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/forensics/collect` | Start forensic collection |
| GET | `/api/forensics/status/:id` | Check collection status |
| GET | `/api/forensics/jobs` | List active collection jobs |
| POST | `/api/forensics/retrieve` | Retrieve artifacts from minion |
| POST | `/api/forensics/cleanup` | Clean old artifacts on minions |
| GET | `/api/forensics/artifacts/:target` | List artifacts on a minion |
| POST | `/api/forensics/quick-collect` | Quick collection (subset) |

### Example: Full Collection Flow

```bash
# 1. Start async collection
RESPONSE=$(curl -s -X POST http://localhost:3000/api/forensics/collect \
  -H "Content-Type: application/json" \
  -H "Cookie: salt-gui.sid=$SESSION" \
  -d '{"targets": "*", "async": true}')

COLLECTION_ID=$(echo $RESPONSE | jq -r '.collection_id')

# 2. Poll for completion
while true; do
  STATUS=$(curl -s "http://localhost:3000/api/forensics/status/$COLLECTION_ID" \
    -H "Cookie: salt-gui.sid=$SESSION" | jq -r '.status')

  if [ "$STATUS" = "completed" ]; then
    break
  fi

  sleep 10
done

# 3. Retrieve artifacts
curl -X POST http://localhost:3000/api/forensics/retrieve \
  -H "Content-Type: application/json" \
  -H "Cookie: salt-gui.sid=$SESSION" \
  -d '{"target": "webserver-01", "tarball_path": "/tmp/forensics_xxx/..."}'
```

## Testing

### Plant Test Artifacts

```bash
# Deploy test artifacts to a minion
salt 'test-minion' cmd.script salt://linux/forensics/files/plant_artifacts.sh

# Or run locally
./scripts/linux/forensics/test/plant_artifacts.sh
```

This creates simulated malicious artifacts:
- Suspicious cron jobs (curl | bash)
- Backdoor user account
- Unauthorized SSH keys
- Malicious systemd service
- ld.so.preload rootkit simulation
- Shell profile backdoors
- Hidden files in /tmp

### Verify Collection

```bash
# After running collection, verify artifacts were captured
./scripts/linux/forensics/test/verify_collection.sh /tmp/forensics_*/minion_*.tar.gz
```

### Analyze Artifacts

```bash
# Analyze collected artifacts for suspicious items
./scripts/linux/forensics/test/analyze_artifacts.sh /tmp/forensics_*/minion_*.tar.gz

# JSON output for parsing
./scripts/linux/forensics/test/analyze_artifacts.sh tarball.tar.gz --json
```

### Clean Up Test Artifacts

```bash
# Remove planted test artifacts
salt 'test-minion' cmd.script salt://linux/forensics/files/plant_artifacts.sh args='--clean'

# Or locally
./scripts/linux/forensics/test/plant_artifacts.sh --clean
```

## Troubleshooting

### Collection Times Out

Increase the timeout:
```bash
salt '*' state.apply linux.forensics pillar='{"forensics": {"collection_timeout": 1200}}'
```

Or via API:
```json
{"targets": "*", "timeout": 1200}
```

### cp.push Fails

1. Ensure `file_recv: True` is set on the master
2. Check master logs: `tail -f /var/log/salt/master`
3. Alternative: Use salt-cp to retrieve manually:
   ```bash
   salt-cp minion-id '/tmp/forensics_*/minion_*.tar.gz' /srv/forensics/
   ```

### Artifacts Missing

1. Check collector script output in Salt job results
2. Verify the file exists on the minion:
   ```bash
   salt minion-id cmd.run 'ls -la /tmp/forensics_*/'
   ```
3. Check for permission issues (script runs as root)

### Large Artifacts

Log files are automatically truncated to 50MB. To adjust:
- Modify `MAX_LOG_SIZE_MB` in `collector.sh`
- Or use pillar configuration

## Security Considerations

- Artifacts may contain sensitive data (passwords, keys, histories)
- Tarballs are created with mode 600 (owner-only)
- Always store artifacts in secure locations
- Delete artifacts after analysis
- Audit log tracks all forensic operations

## Cross-Platform Support

| Distribution | Status |
|--------------|--------|
| Ubuntu/Debian | Full support |
| Rocky/RHEL/Fedora | Full support |
| Alpine Linux | Partial (some tools may differ) |
| Windows | Not supported (separate module planned) |

## Integration with Incident Response

1. **Initial Response**: Run quick-collect for immediate triage
2. **Full Investigation**: Run full collection for detailed analysis
3. **Timeline Analysis**: Correlate artifacts with timestamps
4. **Persistence Hunt**: Focus on cron, systemd, ld.so.preload
5. **User Analysis**: Check for unauthorized accounts and keys
6. **Network Analysis**: Review connections and firewall rules

## Files

```
scripts/linux/forensics/
├── collector.sh              # Main collection script
├── README.md                 # This documentation
└── test/
    ├── plant_artifacts.sh    # Plant test malicious artifacts
    ├── verify_collection.sh  # Verify collection captured artifacts
    └── analyze_artifacts.sh  # Analyze artifacts for IOCs

states/linux/forensics/
├── init.sls                  # Main Salt state
├── collect.sls               # Collection-only state (no push)
├── files/
│   ├── collector.sh          # Collection script for deployment
│   ├── plant_artifacts.sh    # Test script
│   ├── verify_collection.sh  # Verification script
│   └── analyze_artifacts.sh  # Analysis script
└── pillar/
    └── forensics.sls         # Pillar configuration

config/salt-master/
└── forensics.conf            # Salt master configuration
```

## Contributing

When adding new collection modules:
1. Add collection logic to `collector.sh`
2. Update the output structure documentation
3. Add verification checks to `verify_collection.sh`
4. Add analysis rules to `analyze_artifacts.sh`
5. Update this README

## License

MIT License - See LICENSE file in project root.
