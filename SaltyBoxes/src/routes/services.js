/**
 * Services Routes
 *
 * Service management on Salt minions (start, stop, restart, enable, disable).
 * Works with both Linux (systemd/sysvinit) and Windows services.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

/**
 * GET /api/services/:target
 * List all services on target minion(s)
 */
router.get('/:target', async (req, res) => {
  const { target } = req.params;

  try {
    logger.info(`Listing services on ${target}`, { user: req.username });

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.get_all',
      tgt: target,
      tgt_type: target.includes('*') ? 'glob' : 'list'
    });

    if (!result || Object.keys(result).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded or target not found'
      });
    }

    res.json({
      success: true,
      services: result
    });

  } catch (error) {
    logger.error('Failed to list services', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/services/:target/:service/status
 * Get status of a specific service
 */
router.get('/:target/:service/status', async (req, res) => {
  const { target, service } = req.params;

  try {
    logger.info(`Checking service ${service} status on ${target}`, { user: req.username });

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.status',
      tgt: target,
      tgt_type: target.includes('*') ? 'glob' : 'list',
      arg: [service]
    });

    if (!result || Object.keys(result).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded or target not found'
      });
    }

    res.json({
      success: true,
      service: service,
      status: result
    });

  } catch (error) {
    logger.error(`Failed to get status for service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/start
 * Start a service on target minion(s)
 */
router.post('/start', async (req, res) => {
  const { targets, service } = req.body;

  if (!targets || !service) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, service'
    });
  }

  try {
    logger.info(`Starting service ${service}`, {
      user: req.username,
      targets,
      service
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.start',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [service]
    });

    res.json({
      success: true,
      action: 'start',
      service: service,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to start service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/stop
 * Stop a service on target minion(s)
 */
router.post('/stop', async (req, res) => {
  const { targets, service } = req.body;

  if (!targets || !service) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, service'
    });
  }

  try {
    logger.info(`Stopping service ${service}`, {
      user: req.username,
      targets,
      service
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.stop',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [service]
    });

    res.json({
      success: true,
      action: 'stop',
      service: service,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to stop service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/restart
 * Restart a service on target minion(s)
 */
router.post('/restart', async (req, res) => {
  const { targets, service } = req.body;

  if (!targets || !service) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, service'
    });
  }

  try {
    logger.info(`Restarting service ${service}`, {
      user: req.username,
      targets,
      service
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.restart',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [service]
    });

    res.json({
      success: true,
      action: 'restart',
      service: service,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to restart service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/enable
 * Enable a service at boot on target minion(s)
 */
router.post('/enable', async (req, res) => {
  const { targets, service } = req.body;

  if (!targets || !service) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, service'
    });
  }

  try {
    logger.info(`Enabling service ${service}`, {
      user: req.username,
      targets,
      service
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.enable',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [service]
    });

    res.json({
      success: true,
      action: 'enable',
      service: service,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to enable service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/disable
 * Disable a service at boot on target minion(s)
 */
router.post('/disable', async (req, res) => {
  const { targets, service } = req.body;

  if (!targets || !service) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, service'
    });
  }

  try {
    logger.info(`Disabling service ${service}`, {
      user: req.username,
      targets,
      service
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'service.disable',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [service]
    });

    res.json({
      success: true,
      action: 'disable',
      service: service,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to disable service ${service}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/services/bulk
 * Perform bulk service operations
 */
router.post('/bulk', async (req, res) => {
  const { targets, services, action } = req.body;

  const validActions = ['start', 'stop', 'restart', 'enable', 'disable'];

  if (!targets || !services || !action) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, services, action'
    });
  }

  if (!validActions.includes(action)) {
    return res.status(400).json({
      success: false,
      error: `Invalid action. Must be one of: ${validActions.join(', ')}`
    });
  }

  try {
    logger.info(`Bulk service action: ${action}`, {
      user: req.username,
      targets,
      services,
      action
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const serviceList = Array.isArray(services) ? services : [services];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const results = {};

    for (const service of serviceList) {
      try {
        results[service] = await saltClient.run({
          client: 'local',
          fun: `service.${action}`,
          tgt: tgt,
          tgt_type: tgtType,
          arg: [service]
        });
      } catch (err) {
        results[service] = { error: err.message };
      }
    }

    res.json({
      success: true,
      action: action,
      results: results
    });

  } catch (error) {
    logger.error(`Failed bulk service operation`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
