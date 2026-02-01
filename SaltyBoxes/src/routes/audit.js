/**
 * Audit Log Routes
 *
 * Provides access to the audit trail.
 *
 * @module routes/audit
 */

const express = require('express');
const router = express.Router();
const { readAuditLog, clearAuditLog } = require('../lib/logger');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');

// Apply authentication to all audit routes
router.use(requireAuth);

/**
 * GET /api/audit
 * Get audit log entries
 *
 * Query params:
 *   limit: number - Maximum entries to return (default: 100, max: 1000)
 *   action: string - Filter by action type
 *   user: string - Filter by username
 */
router.get('/', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
  const actionFilter = req.query.action;
  const userFilter = req.query.user;

  try {
    let entries = readAuditLog(limit * 2); // Get extra for filtering

    // Apply filters
    if (actionFilter) {
      entries = entries.filter(e => e.action && e.action.includes(actionFilter));
    }
    if (userFilter) {
      entries = entries.filter(e => e.user === userFilter);
    }

    // Limit results
    entries = entries.slice(-limit);

    // Return in reverse chronological order
    entries.reverse();

    res.json({
      success: true,
      count: entries.length,
      entries
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * GET /api/audit/actions
 * Get list of unique action types
 */
router.get('/actions', (req, res) => {
  try {
    const entries = readAuditLog(1000);
    const actions = [...new Set(entries.map(e => e.action).filter(Boolean))];
    actions.sort();

    res.json({
      success: true,
      actions
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * GET /api/audit/users
 * Get list of unique users in audit log
 */
router.get('/users', (req, res) => {
  try {
    const entries = readAuditLog(1000);
    const users = [...new Set(entries.map(e => e.user).filter(Boolean))];
    users.sort();

    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * DELETE /api/audit
 * Clear audit log (admin only)
 */
router.delete('/', requireAdmin, (req, res) => {
  try {
    clearAuditLog();

    res.json({
      success: true,
      message: 'Audit log cleared'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to clear audit log'
    });
  }
});

// ============================================================
// System Audit Endpoints (query minions via Salt)
// ============================================================

/**
 * GET /api/audit/users/:target
 * List users on a target minion
 */
router.get('/users/:target', async (req, res) => {
  const { target } = req.params;
  try {
    const script = `echo "=== Local Users ==="; cat /etc/passwd | awk -F: '{printf "%-20s UID=%-6s GID=%-6s Shell=%s\\n", $1, $3, $4, $7}'; echo ""; echo "=== UID 0 Users ==="; awk -F: '$3==0{print $1}' /etc/passwd; echo ""; echo "=== Users with Login Shells ==="; awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1 " " $7}' /etc/passwd; echo ""; echo "=== Groups ==="; cat /etc/group | awk -F: '{printf "%-20s GID=%-6s Members=%s\\n", $1, $3, $4}'; echo ""; echo "=== Sudoers ==="; cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"; ls /etc/sudoers.d/ 2>/dev/null; echo ""; echo "=== Recently Modified Users ==="; ls -lt /etc/passwd /etc/shadow /etc/group 2>/dev/null`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, audit: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/audit/network/:target
 * Network connections audit on a target minion
 */
router.get('/network/:target', async (req, res) => {
  const { target } = req.params;
  try {
    const script = `echo "=== Listening Ports ==="; ss -tlnp 2>/dev/null; echo ""; echo "=== Established Connections ==="; ss -tnp state established 2>/dev/null; echo ""; echo "=== All Sockets ==="; ss -anp 2>/dev/null | head -50; echo ""; echo "=== IP Addresses ==="; ip addr 2>/dev/null; echo ""; echo "=== Routes ==="; ip route 2>/dev/null; echo ""; echo "=== ARP Cache ==="; ip neigh 2>/dev/null; echo ""; echo "=== DNS Config ==="; cat /etc/resolv.conf 2>/dev/null; echo ""; echo "=== Firewall Rules ==="; iptables -L -n -v 2>/dev/null | head -40`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, audit: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/audit/files/:target
 * File integrity audit on a target minion
 */
router.get('/files/:target', async (req, res) => {
  const { target } = req.params;
  try {
    const script = `echo "=== SUID Files ==="; find / -perm -4000 -type f -ls 2>/dev/null | head -30; echo ""; echo "=== SGID Files ==="; find / -perm -2000 -type f -ls 2>/dev/null | head -30; echo ""; echo "=== World-Writable Files ==="; find /etc /usr /var -type f -perm -o+w -ls 2>/dev/null | head -20; echo ""; echo "=== Recently Modified in /etc ==="; find /etc -type f -mmin -60 -ls 2>/dev/null | head -20; echo ""; echo "=== Hidden Files in /tmp ==="; find /tmp -name ".*" -ls 2>/dev/null; echo ""; echo "=== /dev/shm Contents ==="; ls -la /dev/shm/ 2>/dev/null`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, audit: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
