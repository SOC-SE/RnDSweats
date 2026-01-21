# Salt Functions Quick Reference for CCDC

## Understanding Salt Functions

Salt functions follow the format: `module.function`

When you select "Salt Functions" in the GUI, you're calling Salt modules directly on the minions. This is incredibly powerful for system administration.

## Essential Functions for Competition

### System Information
```
grains.items          - Get all system facts (OS, IP, memory, etc.)
grains.item os        - Get specific grain (e.g., operating system)
status.uptime         - System uptime
status.loadavg        - CPU load average
status.meminfo        - Memory information
status.diskusage      - Disk usage
```

### User Management
```
user.list_users       - List all users
user.info <username>  - Get user details
user.add <name>       - Add user
user.delete <name>    - Delete user
user.chpassword <name> <password>  - Change password
shadow.info <username> - Get password aging info
group.getent          - List all groups
```

### File Operations
```
file.read /etc/passwd            - Read file contents
file.write /path "content"       - Write to file
file.append /path "line"         - Append to file
file.directory_exists /path      - Check if directory exists
file.file_exists /path           - Check if file exists
file.get_mode /path              - Get file permissions
file.set_mode /path 0644         - Set file permissions
file.chown /path user group      - Change ownership
file.find /path name="*.sh"      - Find files
```

### Process Management
```
ps.pgrep <name>       - Find process by name
ps.pkill <name>       - Kill process by name
ps.top                - Top processes by CPU
status.procs          - Process list
```

### Service Management
```
service.status <name>    - Check service status
service.start <name>     - Start service
service.stop <name>      - Stop service
service.restart <name>   - Restart service
service.enable <name>    - Enable at boot
service.disable <name>   - Disable at boot
service.get_running      - List running services
service.get_enabled      - List enabled services
```

### Network
```
network.interfaces       - List network interfaces
network.ip_addrs         - Get IP addresses
network.netstat          - Network connections
network.active_tcp        - Active TCP connections
network.traceroute <host> - Trace route
network.ping <host>      - Ping host
```

### Package Management
```
# Debian/Ubuntu
pkg.list_pkgs            - List installed packages
pkg.install <name>       - Install package
pkg.remove <name>        - Remove package
pkg.upgrade              - Upgrade all packages

# RHEL/CentOS
pkg.list_pkgs
pkg.install <name>
pkg.remove <name>
```

### Firewall (iptables)
```
iptables.get_rules       - List all rules
iptables.flush           - Flush all rules (DANGEROUS!)
iptables.append <chain> rule=<rule>  - Add rule
```

### Cron Jobs
```
cron.list_tab <user>     - List cron jobs
cron.rm_job <user> <id>  - Remove cron job
```

### Command Execution
```
cmd.run "command"        - Run shell command
cmd.run_all "command"    - Run with full output (stdout, stderr, retcode)
cmd.script salt://path   - Run script from salt fileserver
cmd.shell "command"      - Run in shell (supports pipes, etc.)
```

## Competition-Specific Functions

### Quick Security Audit
```
# Check for unauthorized users
user.list_users

# Check running services
service.get_running

# Check network connections
network.active_tcp

# Check scheduled tasks
cron.list_tab root

# Check sudo access
file.read /etc/sudoers
```

### Quick Hardening
```
# Disable a service
service.stop <malicious_service>
service.disable <malicious_service>

# Remove unauthorized user
user.delete <username>

# Change passwords
user.chpassword root "newpassword"

# Check file permissions
file.get_mode /etc/shadow
```

## Using Arguments in the GUI

When using Salt Functions in the GUI:

1. Select the function from the list
2. Arguments appear in the "Manual Arguments" field
3. Enter comma-separated arguments

Example for `user.chpassword`:
- Manual Arguments: `root,NewSecurePass123!`

Example for `file.read`:
- Manual Arguments: `/etc/passwd`

Example for `cmd.run`:
- Manual Arguments: `ps aux | grep suspicious`

## Tips

1. **Start with grains.items** - This gives you a full picture of the system
2. **Use cmd.run for complex tasks** - When Salt modules don't cover it
3. **service.get_running is gold** - Quickly spot unauthorized services
4. **network.active_tcp for connections** - See who's connected
5. **user.list_users frequently** - Watch for new accounts

## Common Targets

In the device list, you can use glob patterns:
- `*` - All minions
- `web*` - All minions starting with "web"
- `*.comp.local` - All minions in comp.local domain

## Troubleshooting

If functions load slowly:
1. This is normal for `sys.list_functions` - it queries the minion
2. Use the search box to filter instead of scrolling
3. Common functions are always: cmd.run, service.*, pkg.*, user.*

If commands timeout:
1. Check the Salt Master logs: `journalctl -u salt-master`
2. Check minion connectivity: `salt '*' test.ping`
3. Check Salt API: `systemctl status salt-api`
