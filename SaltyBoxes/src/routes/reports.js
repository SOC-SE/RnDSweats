/**
 * Reports Routes
 *
 * Generates and exports reports about system status,
 * audit logs, and suspicious findings.
 *
 * @module routes/reports
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const { readAuditLog } = require('../lib/logger');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all report routes
router.use(requireAuth);

/**
 * GET /api/reports/status
 * Generate system status report
 */
router.get('/status', auditAction('reports.status'), async (req, res) => {
  try {
    // Get all minion keys
    const keysResult = await saltClient.run({
      client: 'wheel',
      fun: 'key.list_all'
    });

    const keys = keysResult?.return?.[0]?.data?.return || keysResult;
    const accepted = keys.minions || [];

    // Get online/offline status and grains in parallel
    const [statusResult, grainsResult] = await Promise.all([
      saltClient.status(),
      saltClient.run({
        client: 'local',
        tgt: '*',
        fun: 'grains.item',
        arg: ['kernel', 'os', 'os_family', 'ipv4'],
        kwarg: { timeout: 30 }
      })
    ]);

    const onlineMinions = new Set(statusResult.up || []);
    // Build a pseudo ping result from status
    const pingResult = {};
    for (const m of accepted) {
      pingResult[m] = onlineMinions.has(m);
    }

    const minions = [];
    let online = 0;
    let offline = 0;
    let linuxCount = 0;
    let windowsCount = 0;

    for (const minionId of accepted) {
      const isOnline = pingResult[minionId] === true;
      const grains = grainsResult[minionId] || {};

      if (isOnline) online++;
      else offline++;

      const kernel = grains?.kernel || 'Unknown';
      if (kernel === 'Linux') linuxCount++;
      else if (kernel === 'Windows') windowsCount++;

      const ipv4List = grains?.ipv4 || [];
      minions.push({
        id: minionId,
        status: isOnline ? 'online' : 'offline',
        os: grains?.os || 'Unknown',
        osFamily: grains?.os_family || 'Unknown',
        kernel,
        ip: ipv4List.filter(ip => ip !== '127.0.0.1')[0] || 'Unknown'
      });
    }

    const report = {
      generated: new Date().toISOString(),
      summary: {
        total: accepted.length,
        online,
        offline,
        linux: linuxCount,
        windows: windowsCount
      },
      minions
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate status report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * GET /api/reports/audit
 * Generate audit log report
 *
 * Query params:
 *   hours: number - Hours of logs to include (default: 24)
 */
router.get('/audit', auditAction('reports.audit'), async (req, res) => {
  const hours = parseInt(req.query.hours, 10) || 24;

  try {
    const entries = readAuditLog(10000);

    // Filter by time
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    const filtered = entries.filter(e => {
      if (!e.timestamp) return false;
      return new Date(e.timestamp).getTime() >= cutoff;
    });

    // Generate summary
    const actionCounts = {};
    const userCounts = {};

    for (const entry of filtered) {
      const action = entry.action || 'unknown';
      const user = entry.user || 'unknown';

      actionCounts[action] = (actionCounts[action] || 0) + 1;
      userCounts[user] = (userCounts[user] || 0) + 1;
    }

    // Sort entries by timestamp (newest first)
    filtered.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    const report = {
      generated: new Date().toISOString(),
      period: `Last ${hours} hours`,
      summary: {
        totalActions: filtered.length,
        byAction: actionCounts,
        byUser: userCounts
      },
      entries: filtered.slice(0, 500) // Limit entries in report
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate audit report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * POST /api/reports/security
 * Generate security scan report for specified targets
 *
 * Body:
 *   targets: string[] - Target minions to scan
 */
router.post('/security', auditAction('reports.security'), async (req, res) => {
  const { targets } = req.body;

  if (!targets || (Array.isArray(targets) && targets.length === 0)) {
    return res.status(400).json({
      success: false,
      error: 'Targets are required'
    });
  }

  const targetList = Array.isArray(targets) ? targets : [targets];

  try {
    const findings = {};
    let totalCritical = 0;
    let totalHigh = 0;
    let totalMedium = 0;
    let totalLow = 0;

    // Import suspicious scanner logic
    const suspiciousRouter = require('./suspicious');

    for (const target of targetList) {
      findings[target] = {
        scanned: new Date().toISOString(),
        findings: []
      };

      // Determine OS (uses kernel cache)
      const kernel = await saltClient.getKernel(target);
      findings[target].kernel = kernel;

      // Quick security checks based on OS
      if (kernel === 'Linux') {
        // Check for UID 0 users
        const uidCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ["awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd"],
          kwarg: { timeout: 30 }
        });

        if (uidCheck[target] && uidCheck[target].trim()) {
          findings[target].findings.push({
            severity: 'critical',
            category: 'Users',
            finding: 'Non-root users with UID 0',
            details: uidCheck[target].trim()
          });
        }

        // Check for SUID in temp
        const suidCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ["find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | head -5"],
          kwarg: { timeout: 60 }
        });

        if (suidCheck[target] && suidCheck[target].trim()) {
          findings[target].findings.push({
            severity: 'critical',
            category: 'Files',
            finding: 'SUID binaries in temp directories',
            details: suidCheck[target].trim()
          });
        }
      } else if (kernel === 'Windows') {
        // Windows security checks

        // Check if Guest account is enabled
        const guestCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ['(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled'],
          kwarg: { shell: 'powershell', timeout: 30 }
        });

        if (guestCheck[target]?.trim() === 'True') {
          findings[target].findings.push({
            severity: 'high',
            category: 'Users',
            finding: 'Guest account is enabled',
            details: 'The Guest account should be disabled for security'
          });
        }

        // Check if Windows Firewall is disabled on any profile
        const fwCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ['Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false} | Select-Object -ExpandProperty Name'],
          kwarg: { shell: 'powershell', timeout: 30 }
        });

        if (fwCheck[target]?.trim()) {
          findings[target].findings.push({
            severity: 'critical',
            category: 'Firewall',
            finding: 'Windows Firewall disabled',
            details: `Firewall disabled on: ${fwCheck[target].trim().replace(/\n/g, ', ')}`
          });
        }

        // Check if RDP is enabled
        const rdpCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ['(Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections'],
          kwarg: { shell: 'powershell', timeout: 30 }
        });

        if (rdpCheck[target]?.trim() === '0') {
          findings[target].findings.push({
            severity: 'medium',
            category: 'Remote Access',
            finding: 'Remote Desktop is enabled',
            details: 'RDP is enabled - ensure it is properly secured'
          });
        }

        // Check for unquoted service paths (privilege escalation vector)
        // Use cmd.powershell for complex PowerShell pipelines
        const unquotedCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.powershell',
          arg: ["Get-CimInstance Win32_Service | Where-Object { ($_.PathName -notlike '\"*') -and ($_.PathName -like '* *') } | Select-Object -First 5 -ExpandProperty Name"],
          kwarg: { timeout: 60 }
        });

        // cmd.powershell returns an array, check if it has results
        const unquotedResult = unquotedCheck[target];
        if (unquotedResult && Array.isArray(unquotedResult) && unquotedResult.length > 0) {
          findings[target].findings.push({
            severity: 'high',
            category: 'Services',
            finding: 'Unquoted service paths found',
            details: unquotedResult.join(', ')
          });
        } else if (unquotedResult && typeof unquotedResult === 'string' && unquotedResult.trim()) {
          findings[target].findings.push({
            severity: 'high',
            category: 'Services',
            finding: 'Unquoted service paths found',
            details: unquotedResult.trim().replace(/\n/g, ', ')
          });
        }
      }

      // Count findings
      for (const f of findings[target].findings) {
        switch (f.severity) {
          case 'critical': totalCritical++; break;
          case 'high': totalHigh++; break;
          case 'medium': totalMedium++; break;
          case 'low': totalLow++; break;
        }
      }
    }

    const report = {
      generated: new Date().toISOString(),
      targets: targetList,
      summary: {
        totalTargets: targetList.length,
        critical: totalCritical,
        high: totalHigh,
        medium: totalMedium,
        low: totalLow,
        total: totalCritical + totalHigh + totalMedium + totalLow
      },
      findings
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate security report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * POST /api/reports/comprehensive
 * Generate comprehensive system report for targets
 * Includes: status, security checks, users, services, processes, log file listing
 */
router.post('/comprehensive', auditAction('reports.comprehensive'), async (req, res) => {
  const { targets } = req.body;

  if (!targets || (Array.isArray(targets) && targets.length === 0)) {
    return res.status(400).json({ success: false, error: 'Targets are required' });
  }

  const targetStr = Array.isArray(targets) ? targets.join(',') : targets;

  try {
    // Run all collection commands in parallel
    const [statusInfo, users, services, processes, logFiles, networkInfo] = await Promise.all([
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['hostname -f 2>/dev/null; echo "---"; uname -a 2>/dev/null; echo "---"; uptime 2>/dev/null; echo "---"; free -h 2>/dev/null; echo "---"; df -h 2>/dev/null'], kwarg: { timeout: 30 } }),
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['cat /etc/passwd 2>/dev/null | awk -F: \'$3>=1000 || $3==0 {print $1":"$3":"$7}\' || net user 2>nul'], kwarg: { timeout: 30 } }),
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -50 || sc query state= active 2>nul | findstr SERVICE_NAME | head -50'], kwarg: { timeout: 30 } }),
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['ps aux --sort=-%cpu 2>/dev/null | head -25 || tasklist /V 2>nul | head -25'], kwarg: { timeout: 30 } }),
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['find /var/log -type f -printf "%s\\t%T@\\t%p\\n" 2>/dev/null | sort -rn -k2 | head -100'], kwarg: { timeout: 30 } }),
      saltClient.run({ client: 'local', tgt: targetStr, tgt_type: Array.isArray(targets) ? 'list' : 'glob', fun: 'cmd.run', arg: ['ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || netstat -an 2>nul | findstr LISTENING'], kwarg: { timeout: 30 } })
    ]);

    const report = {
      generated: new Date().toISOString(),
      targets: Array.isArray(targets) ? targets : [targets],
      minions: {}
    };

    // Combine results per minion
    const allMinions = new Set([
      ...Object.keys(statusInfo || {}),
      ...Object.keys(users || {}),
      ...Object.keys(services || {}),
      ...Object.keys(processes || {}),
      ...Object.keys(logFiles || {}),
      ...Object.keys(networkInfo || {})
    ]);

    for (const minion of allMinions) {
      report.minions[minion] = {
        status: statusInfo[minion] || 'N/A',
        users: users[minion] || 'N/A',
        running_services: services[minion] || 'N/A',
        top_processes: processes[minion] || 'N/A',
        log_files: logFiles[minion] || 'N/A',
        listening_ports: networkInfo[minion] || 'N/A'
      };
    }

    res.json({ success: true, report });
  } catch (error) {
    logger.error('Failed to generate comprehensive report', error);
    res.status(500).json({ success: false, error: 'Failed to generate report', details: error.message });
  }
});

/**
 * GET /api/reports/export/:type
 * Export report in various formats
 *
 * Params:
 *   type: string - Report type (status, audit, security)
 *
 * Query params:
 *   format: string - Export format (json, csv, text) - default: json
 */
router.get('/export/:type', async (req, res) => {
  const { type } = req.params;
  const format = req.query.format || 'json';

  // Redirect to appropriate report endpoint
  const reportTypes = ['status', 'audit'];

  if (!reportTypes.includes(type)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid report type'
    });
  }

  try {
    // This is a placeholder - in a real implementation,
    // we would generate the report and format it accordingly
    res.json({
      success: true,
      message: `Export ${type} report in ${format} format`,
      note: 'Use the /api/reports/:type endpoints to get report data'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Export failed'
    });
  }
});

module.exports = router;
