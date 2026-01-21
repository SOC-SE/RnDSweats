# Salt GUI - Competition Edition

A comprehensive web-based management interface for SaltStack designed for CCDC-style cyber defense competitions. This enhanced version includes security hardening, cross-browser support, emergency controls, and extensive server management capabilities.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Or with auto-reload during development
npm run dev
```

Then open `http://localhost:3000` in your browser (Firefox, Chrome, Safari, Edge all supported).

## 📋 Features

### Security Improvements
- **Session-based authentication** (optional) with configurable timeout
- **Rate limiting** (100 requests/minute per IP)
- **Comprehensive audit logging** to `./audit.log`
- **Input sanitization** for all user-provided data
- **Path traversal prevention** for script operations
- **Minion ID validation** to prevent injection attacks

### Cross-Browser Support
- Full Firefox compatibility (terminal, modals, CSS)
- Safari/WebKit support
- Edge/Chromium support
- Standard-compliant CSS with vendor prefixes
- Universal event handling

### Emergency Controls 🚨
- **Block All Traffic** - Instant iptables lockdown with SSH exception
- **Kill Connections** - Terminate network connections by port
- **Mass Password Change** - Change passwords across multiple devices/users instantly

### System Management

#### Monitoring Tab
- Firewall rules viewer (iptables/nftables/firewalld auto-detection)
- Running processes viewer
- Network connections monitor
- System information display
- User list viewer
- Service status dashboard

#### Services Tab
- Start/Stop/Restart services
- Enable/Disable services at boot
- Real-time service status
- Common services quick-access

#### Playbooks Tab
- Pre-built incident response playbooks
- Custom playbook execution
- Step-by-step execution tracking
- Target device selection
- Execution results display

#### Audit Log Tab
- Complete action history
- User/IP tracking
- Action filtering
- Details inspection

### Terminal Features
- Full terminal modal with scrolling history
- Quick terminal in main view
- Command history (up/down arrows)
- Cross-browser compatible input handling
- Clear with Ctrl+L
- Close with Escape

### Script Management
- Custom scripts (shell, PowerShell, Python, Ruby, Perl)
- Salt built-in functions
- Script viewer with syntax highlighting
- Dynamic argument detection
- Manual argument input
- Append command support (piping)
- Context menu (right-click)

## 📁 Directory Structure

```
salt-gui-improved/
├── server.js           # Enhanced backend server
├── index.html          # Modern tabbed UI
├── script.js           # Cross-browser frontend
├── style.css           # Responsive CSS
├── package.json        # Dependencies
├── config.json         # Auto-generated settings (don't commit!)
├── audit.log           # Action audit trail
├── jobs.json           # Persistent job tracking
├── output_history.json # Command history
└── playbooks/          # Incident response playbooks
    ├── ssh-hardening.json
    ├── firewall-lockdown.json
    ├── threat-hunt-persistence.json
    ├── user-audit.json
    └── system-status.json
```

## ⚙️ Configuration

Settings are stored in `config.json` (auto-created on first run):

```json
{
  "proxyURL": "http://localhost:3000",
  "saltAPIUrl": "https://your-salt-master:8000",
  "username": "saltapi",
  "password": "your-secure-password",
  "eauth": "pam",
  "asyncJobTimeout": 300000,
  "maxConcurrentJobs": 10,
  "enableAuth": false,
  "authPassword": "",
  "alertWebhook": ""
}
```

### Settings Explained
- `proxyURL`: URL where this server runs
- `saltAPIUrl`: Your Salt API endpoint
- `username/password`: Salt API credentials
- `eauth`: Authentication backend (pam, ldap, etc.)
- `asyncJobTimeout`: Max time for async jobs (ms)
- `maxConcurrentJobs`: Parallel job limit
- `enableAuth`: Enable GUI authentication
- `authPassword`: Password for GUI access
- `alertWebhook`: URL for critical alert notifications

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/login` - Login (if enabled)
- `POST /api/auth/logout` - Logout

### Core Operations
- `POST /proxy` - Execute Salt commands
- `POST /proxy/async` - Async job submission
- `GET /proxy/job/:jid` - Check async job status
- `POST /api/quick-cmd` - Quick command execution

### Emergency Controls
- `POST /api/emergency/block-all-traffic` - Firewall lockdown
- `POST /api/emergency/kill-connections` - Kill connections
- `POST /api/emergency/change-passwords` - Mass password change

### Services
- `POST /api/services/status` - Get service status
- `POST /api/services/manage` - Start/stop/restart services

### Playbooks
- `GET /api/playbooks` - List available playbooks
- `GET /api/playbooks/:name` - Get playbook details
- `POST /api/playbooks/:name/execute` - Execute playbook

### Monitoring
- `GET /api/health` - System health check
- `GET /api/minions/status` - Minion status
- `GET /api/minions/grains` - Cached grains data
- `POST /api/network/connections` - Network connections
- `POST /api/users/list` - List users

### File Operations
- `POST /api/files/read` - Read file from minion
- `POST /api/files/write` - Write file to minion

### Key Management
- `GET /keys` - List all keys
- `POST /keys/accept` - Accept a key
- `POST /keys/accept-all` - Accept all pending keys
- `POST /keys/delete` - Delete a key

### Audit
- `GET /api/audit` - Get audit log entries

## 📚 Included Playbooks

### SSH Hardening (`ssh-hardening.json`)
Hardens SSH configuration:
- Disables root login
- Disables password authentication
- Sets protocol to SSH-2
- Disables empty passwords
- Sets max auth tries to 3

### Firewall Lockdown (`firewall-lockdown.json`)
Configures restrictive iptables:
- Default DROP policies
- Allows loopback and established
- Opens SSH, HTTP, HTTPS, Salt ports
- Logs dropped packets

### Threat Hunt - Persistence (`threat-hunt-persistence.json`)
Searches for attacker persistence:
- Crontabs for all users
- Cron directories
- Systemd services
- SUID binaries
- Unusual shells
- Authorized keys
- Hidden files in /tmp
- Kernel modules
- Network connections

### User Audit (`user-audit.json`)
Audits user accounts:
- Login shells
- UID 0 accounts
- Sudoers
- Password-less sudo
- Recent logins
- Empty passwords
- Current sessions
- SSH keys

### System Status (`system-status.json`)
Quick health check:
- Uptime and load
- Memory usage
- Disk usage
- Top CPU processes
- Listening services
- Established connections
- Failed logins
- Critical services
- System errors

## 🔐 Security Recommendations

1. **Enable GUI authentication** (`enableAuth: true`)
2. **Set a strong authPassword**
3. **Use HTTPS** with a reverse proxy (nginx/Caddy)
4. **Configure alertWebhook** for critical event notifications
5. **Review audit.log** regularly
6. **Restrict network access** to the management port
7. **Don't commit config.json** (contains credentials)

## 🖥️ Competition Tips

### Quick Commands
- Use the quick terminal for rapid command execution
- Keyboard shortcuts: Ctrl+L (clear), Escape (close modals)
- Command history with up/down arrows

### Emergency Response
1. Click 🚨 for emergency controls
2. **Block Traffic**: Instant firewall lockdown
3. **Kill Connections**: Stop active attacks
4. **Change Passwords**: Lock out attackers

### Playbook Usage
1. Go to Playbooks tab
2. Select a playbook
3. Choose target devices
4. Execute and monitor progress

### Best Practices
- Always have SSH access preserved (Block Traffic does this)
- Run User Audit first to understand the environment
- Use Threat Hunt to find attacker persistence
- Apply SSH Hardening on all boxes
- Monitor audit log for team accountability

## 🐛 Troubleshooting

### Terminal not working
- Ensure JavaScript is enabled
- Check browser console for errors
- Try refreshing the page

### Salt API connection failed
- Verify `saltAPIUrl` in settings
- Check Salt API is running: `systemctl status salt-api`
- Verify credentials
- Check firewall allows connection

### Devices not showing
- Check Salt master: `salt-key -L`
- Accept pending keys via UI
- Verify minion connectivity: `salt '*' test.ping`

### Firefox-specific issues
- Clear browser cache
- Disable extensions temporarily
- Check for CSS-related console errors

## 📝 Creating Custom Playbooks

Create a JSON file in `./playbooks/`:

```json
{
  "name": "My Playbook",
  "description": "Description of what it does",
  "category": "hardening",
  "severity": "medium",
  "steps": [
    {
      "name": "Step 1",
      "function": "cmd.run",
      "command": "echo 'Hello World'",
      "timeout": 10000,
      "required": true
    }
  ]
}
```

### Step Options
- `name`: Display name
- `function`: Salt function (cmd.run, service.restart, etc.)
- `command`: Command to run (for cmd.run)
- `args`: Array of arguments (for other functions)
- `kwargs`: Key-value arguments
- `timeout`: Max execution time (ms)
- `required`: Stop on failure if true
- `stopOnError`: Same as required

## 📄 License

ISC License - Samuel Brucker 2025-2026

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test in multiple browsers
5. Submit a pull request

---

Made with 🧂 for CCDC competitors
