/**
 * Device (Minion) Routes
 *
 * Handles minion listing, status, grains, and key management.
 *
 * @module routes/devices
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');

// Apply authentication to all device routes
router.use(requireAuth);

// Cache for device data
let deviceCache = {
  devices: [],
  lastUpdate: 0,
  ttl: 30000 // 30 seconds
};

/**
 * GET /api/devices
 * List all minions with status and basic info
 */
router.get('/', async (req, res) => {
  const forceRefresh = req.query.refresh === 'true';

  try {
    // Check cache
    const now = Date.now();
    if (!forceRefresh && deviceCache.devices.length > 0 &&
        (now - deviceCache.lastUpdate) < deviceCache.ttl) {
      return res.json({
        success: true,
        cached: true,
        devices: deviceCache.devices,
        count: deviceCache.devices.length
      });
    }

    // Get minion keys
    const keys = await saltClient.listKeys();
    const acceptedMinions = keys?.minions || [];

    if (acceptedMinions.length === 0) {
      deviceCache.devices = [];
      deviceCache.lastUpdate = now;

      return res.json({
        success: true,
        devices: [],
        count: 0
      });
    }

    // Get status (up/down)
    const status = await saltClient.status();
    const upMinions = new Set(status.up || []);

    // Get grains for online minions (basic set for listing)
    let grainsData = {};
    if (upMinions.size > 0) {
      try {
        grainsData = await saltClient.grainsItem(
          Array.from(upMinions),
          ['os', 'os_family', 'kernel', 'ipv4', 'fqdn', 'cpu_model', 'mem_total']
        );
        // Populate kernel cache for faster subsequent requests
        const kernelData = {};
        for (const [minionId, grains] of Object.entries(grainsData)) {
          if (grains?.kernel) {
            kernelData[minionId] = { kernel: grains.kernel };
          }
        }
        saltClient.populateKernelCache(kernelData);
      } catch (err) {
        logger.warn('Failed to fetch grains', { error: err.message });
      }
    }

    // Build device list
    const devices = acceptedMinions.map(minionId => {
      const isOnline = upMinions.has(minionId);
      const grains = grainsData[minionId] || {};

      // Extract primary IP with smart selection
      // Priority: 1) Private network IPs (192.168.x, 172.16-31.x), 2) Other non-NAT IPs, 3) NAT IPs
      const ipv4 = grains.ipv4 || [];
      const validIps = ipv4.filter(ip => ip !== '127.0.0.1');

      // Prefer 192.168.x.x or 172.16-31.x.x (typical private networks)
      // Deprioritize 10.0.2.x (VirtualBox NAT) and other 10.x.x.x ranges
      const preferredIp = validIps.find(ip =>
        ip.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)
      );
      const fallbackIp = validIps.find(ip => !ip.startsWith('10.0.2.'));
      const primaryIp = preferredIp || fallbackIp || validIps[0] || 'unknown';

      return {
        id: minionId,
        status: isOnline ? 'online' : 'offline',
        os: grains.os || 'unknown',
        os_family: grains.os_family || 'unknown',
        kernel: grains.kernel || 'unknown',
        ip: primaryIp,
        ip_addresses: ipv4,
        fqdn: grains.fqdn || minionId,
        cpu: grains.cpu_model || 'unknown',
        memory_mb: grains.mem_total || 0
      };
    });

    // Sort: online first, then alphabetically
    devices.sort((a, b) => {
      if (a.status !== b.status) {
        return a.status === 'online' ? -1 : 1;
      }
      return a.id.localeCompare(b.id);
    });

    // Update cache
    deviceCache.devices = devices;
    deviceCache.lastUpdate = now;

    res.json({
      success: true,
      cached: false,
      devices,
      count: devices.length,
      online: devices.filter(d => d.status === 'online').length,
      offline: devices.filter(d => d.status === 'offline').length
    });
  } catch (error) {
    logger.error('Failed to list devices', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve devices',
      details: error.message
    });
  }
});

/**
 * GET /api/devices/:id
 * Get detailed information about a specific minion
 */
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  // Validate minion ID
  if (!id || !/^[a-zA-Z0-9._-]+$/.test(id)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid minion ID'
    });
  }

  try {
    // Ping to check if online
    const pingResult = await saltClient.ping(id);
    const isOnline = pingResult[id] === true;

    if (!isOnline) {
      return res.json({
        success: true,
        device: {
          id,
          status: 'offline',
          message: 'Minion is not responding'
        }
      });
    }

    // Get full grains
    const grainsResult = await saltClient.grains(id);
    const grains = grainsResult[id] || {};

    // Extract useful information
    const device = {
      id,
      status: 'online',
      os: grains.os,
      os_family: grains.os_family,
      osrelease: grains.osrelease,
      kernel: grains.kernel,
      kernelrelease: grains.kernelrelease,
      fqdn: grains.fqdn,
      host: grains.host,
      ip_addresses: grains.ipv4 || [],
      ip6_addresses: grains.ipv6 || [],
      mac_addresses: grains.hwaddr_interfaces || {},
      cpu_model: grains.cpu_model,
      cpu_count: grains.num_cpus,
      memory_mb: grains.mem_total,
      virtual: grains.virtual,
      manufacturer: grains.manufacturer,
      productname: grains.productname,
      saltversion: grains.saltversion,
      pythonversion: grains.pythonversion ? grains.pythonversion.join('.') : 'unknown'
    };

    res.json({
      success: true,
      device
    });
  } catch (error) {
    logger.error(`Failed to get device ${id}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve device information',
      details: error.message
    });
  }
});

/**
 * GET /api/devices/:id/grains
 * Get all grains for a specific minion
 */
router.get('/:id/grains', async (req, res) => {
  const { id } = req.params;

  if (!id || !/^[a-zA-Z0-9._-]+$/.test(id)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid minion ID'
    });
  }

  try {
    const result = await saltClient.grains(id);
    const grains = result[id];

    if (!grains || typeof grains === 'string') {
      return res.status(404).json({
        success: false,
        error: 'Minion not responding or not found'
      });
    }

    res.json({
      success: true,
      minion: id,
      grains
    });
  } catch (error) {
    logger.error(`Failed to get grains for ${id}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve grains',
      details: error.message
    });
  }
});

/**
 * POST /api/devices/ping
 * Ping specific minions
 */
router.post('/ping', async (req, res) => {
  const { targets } = req.body;

  if (!targets || (Array.isArray(targets) && targets.length === 0)) {
    return res.status(400).json({
      success: false,
      error: 'Targets are required'
    });
  }

  try {
    const target = Array.isArray(targets) ? targets : targets;
    const result = await saltClient.ping(target);

    const online = [];
    const offline = [];

    for (const [minion, status] of Object.entries(result)) {
      if (status === true) {
        online.push(minion);
      } else {
        offline.push(minion);
      }
    }

    res.json({
      success: true,
      results: result,
      summary: {
        online: online.length,
        offline: offline.length,
        onlineMinions: online,
        offlineMinions: offline
      }
    });
  } catch (error) {
    logger.error('Ping failed', error);
    res.status(500).json({
      success: false,
      error: 'Ping operation failed',
      details: error.message
    });
  }
});

/**
 * GET /api/devices/status/summary
 * Get quick status summary
 */
router.get('/status/summary', async (req, res) => {
  try {
    const status = await saltClient.status();

    res.json({
      success: true,
      up: status.up || [],
      down: status.down || [],
      counts: {
        online: (status.up || []).length,
        offline: (status.down || []).length,
        total: (status.up || []).length + (status.down || []).length
      }
    });
  } catch (error) {
    logger.error('Status check failed', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check status',
      details: error.message
    });
  }
});

/**
 * GET /api/devices/os/groups
 * Get minions grouped by OS
 */
router.get('/os/groups', async (req, res) => {
  try {
    // Get OS grains for all minions
    const grainsResult = await saltClient.grainsItem('*', ['os', 'os_family', 'kernel']);

    const groups = {
      linux: [],
      windows: [],
      other: []
    };

    for (const [minion, grains] of Object.entries(grainsResult)) {
      if (!grains || typeof grains === 'string') continue;

      const kernel = (grains.kernel || '').toLowerCase();
      const osFamily = (grains.os_family || '').toLowerCase();

      if (kernel === 'windows' || osFamily === 'windows') {
        groups.windows.push({
          id: minion,
          os: grains.os,
          os_family: grains.os_family
        });
      } else if (kernel === 'linux' ||
                 ['debian', 'redhat', 'arch', 'suse', 'gentoo'].includes(osFamily)) {
        groups.linux.push({
          id: minion,
          os: grains.os,
          os_family: grains.os_family
        });
      } else {
        groups.other.push({
          id: minion,
          os: grains.os,
          os_family: grains.os_family,
          kernel: grains.kernel
        });
      }
    }

    res.json({
      success: true,
      groups,
      counts: {
        linux: groups.linux.length,
        windows: groups.windows.length,
        other: groups.other.length
      }
    });
  } catch (error) {
    logger.error('Failed to group by OS', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve OS groups',
      details: error.message
    });
  }
});

// ============================================================
// Key Management
// ============================================================

/**
 * GET /api/devices/keys/all
 * List all minion keys by status
 */
router.get('/keys/all', async (req, res) => {
  try {
    const keys = await saltClient.listKeys();

    res.json({
      success: true,
      keys: {
        accepted: keys.minions || [],
        pending: keys.minions_pre || [],
        rejected: keys.minions_rejected || [],
        denied: keys.minions_denied || []
      },
      counts: {
        accepted: (keys.minions || []).length,
        pending: (keys.minions_pre || []).length,
        rejected: (keys.minions_rejected || []).length,
        denied: (keys.minions_denied || []).length
      }
    });
  } catch (error) {
    logger.error('Failed to list keys', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve keys',
      details: error.message
    });
  }
});

/**
 * POST /api/devices/keys/accept
 * Accept a minion key
 */
router.post('/keys/accept', async (req, res) => {
  const { minionId } = req.body;

  if (!minionId || !/^[a-zA-Z0-9._-]+$/.test(minionId)) {
    return res.status(400).json({
      success: false,
      error: 'Valid minion ID is required'
    });
  }

  try {
    await saltClient.acceptKey(minionId);

    logger.info(`Key accepted for ${minionId}`);

    res.json({
      success: true,
      message: `Key accepted for ${minionId}`
    });
  } catch (error) {
    logger.error(`Failed to accept key for ${minionId}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to accept key',
      details: error.message
    });
  }
});

/**
 * POST /api/devices/keys/accept-all
 * Accept all pending minion keys
 */
router.post('/keys/accept-all', async (req, res) => {
  try {
    // First get pending keys
    const keys = await saltClient.listKeys();
    const pending = keys.minions_pre || [];

    if (pending.length === 0) {
      return res.json({
        success: true,
        message: 'No pending keys to accept',
        accepted: []
      });
    }

    // Accept all pending
    await saltClient.run({
      client: 'wheel',
      fun: 'key.accept',
      kwarg: { match: '*' }
    });

    logger.info(`Accepted ${pending.length} pending keys`);

    res.json({
      success: true,
      message: `Accepted ${pending.length} keys`,
      accepted: pending
    });
  } catch (error) {
    logger.error('Failed to accept all keys', error);
    res.status(500).json({
      success: false,
      error: 'Failed to accept keys',
      details: error.message
    });
  }
});

/**
 * POST /api/devices/keys/reject
 * Reject a minion key
 */
router.post('/keys/reject', async (req, res) => {
  const { minionId } = req.body;

  if (!minionId || !/^[a-zA-Z0-9._-]+$/.test(minionId)) {
    return res.status(400).json({
      success: false,
      error: 'Valid minion ID is required'
    });
  }

  try {
    await saltClient.run({
      client: 'wheel',
      fun: 'key.reject',
      kwarg: { match: minionId }
    });

    logger.info(`Key rejected for ${minionId}`);

    res.json({
      success: true,
      message: `Key rejected for ${minionId}`
    });
  } catch (error) {
    logger.error(`Failed to reject key for ${minionId}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to reject key',
      details: error.message
    });
  }
});

/**
 * DELETE /api/devices/keys/:id
 * Delete a minion key
 */
router.delete('/keys/:id', async (req, res) => {
  const { id } = req.params;

  if (!id || !/^[a-zA-Z0-9._-]+$/.test(id)) {
    return res.status(400).json({
      success: false,
      error: 'Valid minion ID is required'
    });
  }

  try {
    await saltClient.deleteKey(id);

    logger.info(`Key deleted for ${id}`);

    // Invalidate cache
    deviceCache.lastUpdate = 0;

    res.json({
      success: true,
      message: `Key deleted for ${id}`
    });
  } catch (error) {
    logger.error(`Failed to delete key for ${id}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete key',
      details: error.message
    });
  }
});

module.exports = router;
