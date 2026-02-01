/**
 * Emergency Routes
 *
 * Emergency actions for rapid incident response.
 * Includes system lockdown that preserves Salt connectivity.
 *
 * WARNING: These actions can disrupt services. Use only in emergencies.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

// Lockdown scripts for Linux and Windows
const LOCKDOWN_LINUX = `#!/bin/bash
# Emergency Lockdown Script - Linux
# Preserves Salt connectivity on ports 4505/4506

set -e

echo "Starting emergency lockdown..."

# Flush existing rules and set default policies
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Salt (critical - preserves minion connectivity)
iptables -A INPUT -p tcp --dport 4505 -j ACCEPT
iptables -A INPUT -p tcp --dport 4506 -j ACCEPT

# Stop common services that red team might exploit
for svc in sshd ssh apache2 httpd nginx vsftpd smbd nmbd telnet proftpd; do
  systemctl stop $svc 2>/dev/null || true
  systemctl disable $svc 2>/dev/null || true
done

# Kill suspicious processes (common backdoor names)
pkill -9 nc 2>/dev/null || true
pkill -9 ncat 2>/dev/null || true
pkill -9 netcat 2>/dev/null || true
pkill -9 socat 2>/dev/null || true

# Save iptables rules
if command -v iptables-save &>/dev/null; then
  iptables-save > /etc/iptables.rules 2>/dev/null || true
fi

echo "Lockdown complete. Only Salt connectivity preserved."
`;

const LOCKDOWN_WINDOWS = `# Emergency Lockdown Script - Windows
# Preserves Salt connectivity on ports 4505/4506

Write-Host "Starting emergency lockdown..."

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

# Remove all existing inbound rules (optional - be careful)
# Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

# Allow Salt minion ports (critical)
New-NetFirewallRule -DisplayName "Salt Minion 4505" -Direction Inbound -Protocol TCP -LocalPort 4505 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Salt Minion 4506" -Direction Inbound -Protocol TCP -LocalPort 4506 -Action Allow -ErrorAction SilentlyContinue

# Stop potentially exploited services
$services = @(
  "W3SVC",           # IIS
  "MSSQLSERVER",     # SQL Server
  "FTPSVC",          # FTP
  "sshd",            # OpenSSH
  "RemoteRegistry",  # Remote Registry
  "TermService"      # Remote Desktop (optional)
)

foreach ($svc in $services) {
  try {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
  } catch {}
}

Write-Host "Lockdown complete. Only Salt connectivity preserved."
`;

const UNLOCK_LINUX = `#!/bin/bash
# Emergency Unlock Script - Linux
# Restores basic connectivity

set -e

echo "Removing lockdown restrictions..."

# Reset iptables to allow all
iptables -F
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Re-enable SSH (common necessity)
systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null || true

echo "Lockdown removed. All traffic now allowed."
`;

const UNLOCK_WINDOWS = `# Emergency Unlock Script - Windows
# Removes firewall restrictions

Write-Host "Removing lockdown restrictions..."

# Disable Windows Firewall (restore to default state)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction NotConfigured

# Remove lockdown rules
Get-NetFirewallRule -DisplayName "Salt Minion*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host "Lockdown removed."
`;

/**
 * POST /api/emergency/lockdown
 * Initiate emergency lockdown on target minions
 */
router.post('/lockdown', async (req, res) => {
  const { targets, confirm } = req.body;

  if (!targets) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: targets'
    });
  }

  if (confirm !== 'LOCKDOWN') {
    return res.status(400).json({
      success: false,
      error: 'Confirmation required. Set confirm="LOCKDOWN" to proceed.'
    });
  }

  try {
    logger.warn('EMERGENCY LOCKDOWN INITIATED', {
      user: req.username,
      targets,
      ip: req.clientIp
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0] === '*' ? 'glob' :
                    target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'glob' ? target[0] : target;

    // Get OS type for each target
    const grains = await saltClient.run({
      client: 'local',
      fun: 'grains.item',
      tgt: tgt,
      tgt_type: tgtType,
      arg: ['kernel']
    });

    if (!grains || Object.keys(grains).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded'
      });
    }

    const results = {};
    let successCount = 0;
    let failCount = 0;

    // Execute lockdown on each minion based on OS
    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';
      const script = kernel === 'Windows' ? LOCKDOWN_WINDOWS : LOCKDOWN_LINUX;
      const shell = kernel === 'Windows' ? 'powershell' : '/bin/bash';

      try {
        const cmdResult = await saltClient.run({
          client: 'local',
          fun: 'cmd.run_all',
          tgt: minion,
          arg: [script],
          kwarg: { shell, timeout: 60 }
        });

        const minionResult = cmdResult[minion];
        results[minion] = {
          kernel,
          retcode: minionResult?.retcode,
          stdout: minionResult?.stdout,
          stderr: minionResult?.stderr,
          success: minionResult?.retcode === 0
        };

        if (minionResult?.retcode === 0) {
          successCount++;
        } else {
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          kernel,
          error: err.message,
          success: false
        };
        failCount++;
      }
    }

    res.json({
      success: true,
      action: 'lockdown',
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Emergency lockdown failed', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/emergency/unlock
 * Remove emergency lockdown from target minions
 */
router.post('/unlock', async (req, res) => {
  const { targets, confirm } = req.body;

  if (!targets) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: targets'
    });
  }

  if (confirm !== 'UNLOCK') {
    return res.status(400).json({
      success: false,
      error: 'Confirmation required. Set confirm="UNLOCK" to proceed.'
    });
  }

  try {
    logger.warn('EMERGENCY UNLOCK INITIATED', {
      user: req.username,
      targets,
      ip: req.clientIp
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0] === '*' ? 'glob' :
                    target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'glob' ? target[0] : target;

    // Get OS type for each target
    const grains = await saltClient.run({
      client: 'local',
      fun: 'grains.item',
      tgt: tgt,
      tgt_type: tgtType,
      arg: ['kernel']
    });

    if (!grains || Object.keys(grains).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded'
      });
    }

    const results = {};
    let successCount = 0;
    let failCount = 0;

    // Execute unlock on each minion based on OS
    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';
      const script = kernel === 'Windows' ? UNLOCK_WINDOWS : UNLOCK_LINUX;
      const shell = kernel === 'Windows' ? 'powershell' : '/bin/bash';

      try {
        const cmdResult = await saltClient.run({
          client: 'local',
          fun: 'cmd.run_all',
          tgt: minion,
          arg: [script],
          kwarg: { shell, timeout: 60 }
        });

        const minionResult = cmdResult[minion];
        results[minion] = {
          kernel,
          retcode: minionResult?.retcode,
          stdout: minionResult?.stdout,
          stderr: minionResult?.stderr,
          success: minionResult?.retcode === 0
        };

        if (minionResult?.retcode === 0) {
          successCount++;
        } else {
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          kernel,
          error: err.message,
          success: false
        };
        failCount++;
      }
    }

    res.json({
      success: true,
      action: 'unlock',
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Emergency unlock failed', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/emergency/kill-sessions
 * Kill all user sessions on target minions
 */
router.post('/kill-sessions', async (req, res) => {
  const { targets, confirm } = req.body;

  if (!targets) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: targets'
    });
  }

  if (confirm !== 'KILL_SESSIONS') {
    return res.status(400).json({
      success: false,
      error: 'Confirmation required. Set confirm="KILL_SESSIONS" to proceed.'
    });
  }

  try {
    logger.warn('Killing all user sessions', {
      user: req.username,
      targets,
      ip: req.clientIp
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    // Get OS type
    const grains = await saltClient.run({
      client: 'local',
      fun: 'grains.item',
      tgt: tgt,
      tgt_type: tgtType,
      arg: ['kernel']
    });

    const results = {};

    for (const [minion, minionGrains] of Object.entries(grains || {})) {
      const kernel = minionGrains?.kernel || 'Linux';

      let command;
      if (kernel === 'Windows') {
        // Log off all users except current session
        command = 'query session | findstr /V "^>" | findstr /V "services" | for /f "tokens=3" %i in (\'findstr /r "^[0-9]"\') do logoff %i 2>nul';
      } else {
        // Kill all user processes (except root and salt)
        command = 'pkill -u $(awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\' /etc/passwd | tr "\\n" ",") 2>/dev/null || true';
      }

      const shell = kernel === 'Windows' ? 'cmd' : '/bin/bash';

      try {
        const cmdResult = await saltClient.run({
          client: 'local',
          fun: 'cmd.run_all',
          tgt: minion,
          arg: [command],
          kwarg: { shell, timeout: 30 }
        });
        results[minion] = cmdResult[minion];
      } catch (err) {
        results[minion] = { error: err.message };
      }
    }

    res.json({
      success: true,
      action: 'kill-sessions',
      results
    });

  } catch (error) {
    logger.error('Failed to kill sessions', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/emergency/custom
 * Execute a custom emergency command
 */
router.post('/custom', async (req, res) => {
  const { targets, command, shell = 'auto', confirm } = req.body;

  if (!targets || !command) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, command'
    });
  }

  if (confirm !== 'CUSTOM_EMERGENCY') {
    return res.status(400).json({
      success: false,
      error: 'Confirmation required. Set confirm="CUSTOM_EMERGENCY" to proceed.'
    });
  }

  try {
    logger.warn('Custom emergency command', {
      user: req.username,
      targets,
      command: command.substring(0, 200), // Log truncated
      ip: req.clientIp
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const kwarg = {
      timeout: 120
    };

    if (shell !== 'auto') {
      kwarg.shell = shell;
    }

    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run_all',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [command],
      kwarg
    });

    res.json({
      success: true,
      action: 'custom',
      results: result
    });

  } catch (error) {
    logger.error('Custom emergency command failed', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
