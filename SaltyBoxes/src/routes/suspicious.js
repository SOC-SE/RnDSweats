/**
 * Suspicious Items Routes
 *
 * Provides detection and reporting of suspicious items on minions.
 * Checks for common indicators of compromise.
 *
 * @module routes/suspicious
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all suspicious routes
router.use(requireAuth);

/**
 * POST /api/suspicious/scan
 * Scan a target for suspicious items
 *
 * Body:
 *   targets: string | string[] - Target minions
 *   checks: string[] - Optional specific checks to run
 */
router.post('/scan', auditAction('suspicious.scan'), async (req, res) => {
  const { targets, checks } = req.body;

  if (!targets || (Array.isArray(targets) && targets.length === 0)) {
    return res.status(400).json({
      success: false,
      error: 'Targets are required'
    });
  }

  const targetList = Array.isArray(targets) ? targets : [targets];

  try {
    const results = {};

    for (const target of targetList) {
      results[target] = {
        suspicious: [],
        scanned: new Date().toISOString()
      };

      // Get kernel type (uses cache for speed)
      const kernel = await saltClient.getKernel(target);

      if (kernel === 'Windows') {
        await scanWindows(target, results[target].suspicious, checks);
      } else {
        await scanLinux(target, results[target].suspicious, checks);
      }

      results[target].total = results[target].suspicious.length;
    }

    res.json({
      success: true,
      results
    });

  } catch (error) {
    logger.error('Suspicious scan failed', error);
    res.status(500).json({
      success: false,
      error: 'Scan failed',
      details: error.message
    });
  }
});

/**
 * GET /api/suspicious/quick/:target
 * Quick scan for most common issues
 */
router.get('/quick/:target', auditAction('suspicious.quick'), async (req, res) => {
  const { target } = req.params;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    const suspicious = [];

    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    if (kernel === 'Windows') {
      await scanWindows(target, suspicious, ['users', 'tasks', 'startup']);
    } else {
      await scanLinux(target, suspicious, ['users', 'cron', 'suid', 'processes']);
    }

    res.json({
      success: true,
      target,
      kernel,
      suspicious,
      total: suspicious.length,
      scanned: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Quick scan failed', error);
    res.status(500).json({
      success: false,
      error: 'Quick scan failed',
      details: error.message
    });
  }
});

/**
 * Scan Linux system for suspicious items
 */
async function scanLinux(target, suspicious, checks) {
  const allChecks = !checks || checks.length === 0;

  // Check for unauthorized users with UID 0
  if (allChecks || checks.includes('users')) {
    try {
      const uidCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd"],
        kwarg: { timeout: 30 }
      });

      const uid0Users = uidCheck[target];
      if (uid0Users && uid0Users.trim()) {
        suspicious.push({
          category: 'Users',
          severity: 'critical',
          finding: 'Non-root users with UID 0',
          details: uid0Users.trim(),
          remediation: 'Remove or disable these users immediately'
        });
      }
    } catch (e) { /* ignore */ }

    // Check for users with empty passwords
    try {
      const emptyPwd = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null | head -20"],
        kwarg: { timeout: 30 }
      });

      const users = emptyPwd[target];
      if (users && users.trim()) {
        suspicious.push({
          category: 'Users',
          severity: 'high',
          finding: 'Users with empty or no password',
          details: users.trim(),
          remediation: 'Set passwords or lock these accounts'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for suspicious cron jobs
  if (allChecks || checks.includes('cron')) {
    try {
      const cronCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["cat /etc/crontab /etc/cron.d/* /var/spool/cron/* 2>/dev/null | grep -E '(curl|wget|nc|bash -i|python.*-c|perl.*-e|/tmp/|/dev/shm/)' | head -10"],
        kwarg: { timeout: 30 }
      });

      const cronResults = cronCheck[target];
      if (cronResults && cronResults.trim()) {
        suspicious.push({
          category: 'Scheduled Tasks',
          severity: 'high',
          finding: 'Suspicious commands in cron',
          details: cronResults.trim(),
          remediation: 'Review and remove unauthorized cron entries'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for SUID binaries in unusual locations
  if (allChecks || checks.includes('suid')) {
    try {
      const suidCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["find /tmp /var/tmp /dev/shm /home -perm -4000 -type f 2>/dev/null | head -10"],
        kwarg: { timeout: 60 }
      });

      const suidFiles = suidCheck[target];
      if (suidFiles && suidFiles.trim()) {
        suspicious.push({
          category: 'Files',
          severity: 'critical',
          finding: 'SUID binaries in unusual locations',
          details: suidFiles.trim(),
          remediation: 'Remove SUID bit or delete these files'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for suspicious processes
  if (allChecks || checks.includes('processes')) {
    try {
      const procCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["ps aux | grep -E '(nc -l|ncat|socat|/tmp/|/dev/shm/|python.*SimpleHTTP|cryptominer|xmrig)' | grep -v grep | head -10"],
        kwarg: { timeout: 30 }
      });

      const procs = procCheck[target];
      if (procs && procs.trim()) {
        suspicious.push({
          category: 'Processes',
          severity: 'high',
          finding: 'Suspicious processes running',
          details: procs.trim(),
          remediation: 'Kill these processes and investigate'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for SSH authorized_keys modifications
  if (allChecks || checks.includes('ssh')) {
    try {
      const sshCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["find /root /home -name authorized_keys -exec wc -l {} \\; 2>/dev/null | awk '$1 > 0 {print}'"],
        kwarg: { timeout: 30 }
      });

      const sshKeys = sshCheck[target];
      if (sshKeys && sshKeys.trim()) {
        suspicious.push({
          category: 'SSH',
          severity: 'medium',
          finding: 'SSH authorized_keys files found',
          details: sshKeys.trim(),
          remediation: 'Review authorized keys for unauthorized entries'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for world-writable files in sensitive locations
  if (allChecks || checks.includes('permissions')) {
    try {
      const writableCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["find /etc /usr -type f -perm -o+w 2>/dev/null | head -10"],
        kwarg: { timeout: 60 }
      });

      const writable = writableCheck[target];
      if (writable && writable.trim()) {
        suspicious.push({
          category: 'Permissions',
          severity: 'high',
          finding: 'World-writable files in sensitive locations',
          details: writable.trim(),
          remediation: 'Fix permissions on these files'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for listening on unusual ports
  if (allChecks || checks.includes('network')) {
    try {
      const portCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ["ss -tlnp 2>/dev/null | grep -E ':(4444|5555|6666|1337|31337|8888|9999|12345)' | head -10"],
        kwarg: { timeout: 30 }
      });

      const ports = portCheck[target];
      if (ports && ports.trim()) {
        suspicious.push({
          category: 'Network',
          severity: 'critical',
          finding: 'Listening on suspicious ports',
          details: ports.trim(),
          remediation: 'Investigate and close unauthorized listeners'
        });
      }
    } catch (e) { /* ignore */ }
  }
}

/**
 * Scan Windows system for suspicious items
 */
async function scanWindows(target, suspicious, checks) {
  const allChecks = !checks || checks.length === 0;

  // Check for unauthorized admin users
  if (allChecks || checks.includes('users')) {
    try {
      const adminCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ['powershell -Command "Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name"'],
        kwarg: { timeout: 30 }
      });

      const admins = adminCheck[target];
      if (admins && admins.trim()) {
        suspicious.push({
          category: 'Users',
          severity: 'medium',
          finding: 'Local Administrators',
          details: admins.trim(),
          remediation: 'Review admin group membership'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for suspicious scheduled tasks
  if (allChecks || checks.includes('tasks')) {
    try {
      const taskCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ['powershell -Command "Get-ScheduledTask | Where-Object {$_.State -eq \'Ready\' -and $_.TaskPath -notlike \'\\\\Microsoft*\'} | Select-Object TaskName, TaskPath | ConvertTo-Json -Compress"'],
        kwarg: { timeout: 60 }
      });

      const tasks = taskCheck[target];
      if (tasks && tasks.trim() && tasks !== '[]' && tasks !== 'null') {
        suspicious.push({
          category: 'Scheduled Tasks',
          severity: 'medium',
          finding: 'Non-Microsoft scheduled tasks',
          details: tasks.substring(0, 500),
          remediation: 'Review scheduled tasks for unauthorized entries'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check startup programs
  if (allChecks || checks.includes('startup')) {
    try {
      const startupCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ['powershell -Command "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ConvertTo-Json -Compress"'],
        kwarg: { timeout: 30 }
      });

      const startup = startupCheck[target];
      if (startup && startup.trim() && startup !== '[]' && startup !== 'null') {
        suspicious.push({
          category: 'Startup',
          severity: 'medium',
          finding: 'Startup programs detected',
          details: startup.substring(0, 500),
          remediation: 'Review startup programs for unauthorized entries'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for unusual services
  if (allChecks || checks.includes('services')) {
    try {
      const svcCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ['powershell -Command "Get-Service | Where-Object {$_.Status -eq \'Running\' -and $_.StartType -eq \'Automatic\' -and $_.Name -notlike \'*Windows*\' -and $_.Name -notlike \'*Microsoft*\'} | Select-Object Name, DisplayName | ConvertTo-Json -Compress"'],
        kwarg: { timeout: 60 }
      });

      const svcs = svcCheck[target];
      if (svcs && svcs.trim() && svcs !== '[]' && svcs !== 'null') {
        suspicious.push({
          category: 'Services',
          severity: 'low',
          finding: 'Non-Windows automatic services',
          details: svcs.substring(0, 500),
          remediation: 'Review running services'
        });
      }
    } catch (e) { /* ignore */ }
  }

  // Check for suspicious network connections
  if (allChecks || checks.includes('network')) {
    try {
      const netCheck = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: ['powershell -Command "Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -notin @(80,443,445,135,139,3389,5985)} | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Compress"'],
        kwarg: { timeout: 30 }
      });

      const net = netCheck[target];
      if (net && net.trim() && net !== '[]' && net !== 'null') {
        suspicious.push({
          category: 'Network',
          severity: 'medium',
          finding: 'Unusual listening ports',
          details: net.substring(0, 500),
          remediation: 'Investigate processes listening on unusual ports'
        });
      }
    } catch (e) { /* ignore */ }
  }
}

module.exports = router;
