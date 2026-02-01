/**
 * Processes Routes
 *
 * Process management on Salt minions (list, kill).
 * Works with both Linux and Windows.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

/**
 * GET /api/processes/:target
 * List processes on target minion(s)
 */
router.get('/:target', async (req, res) => {
  const { target } = req.params;
  const { limit = 50 } = req.query;

  try {
    logger.info(`Listing processes on ${target}`, { user: req.username });

    const result = await saltClient.run({
      client: 'local',
      fun: 'ps.top',
      tgt: target,
      tgt_type: target.includes('*') ? 'glob' : 'list',
      kwarg: { num_processes: parseInt(limit, 10) }
    });

    if (!result || Object.keys(result).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded or target not found'
      });
    }

    res.json({
      success: true,
      processes: result
    });

  } catch (error) {
    logger.error('Failed to list processes', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/processes/:target/detailed
 * Get detailed process list with more info (using cmd.run)
 */
router.get('/:target/detailed', async (req, res) => {
  const { target } = req.params;

  try {
    logger.info(`Getting detailed process list on ${target}`, { user: req.username });

    // First get grains to determine OS
    const grains = await saltClient.run({
      client: 'local',
      fun: 'grains.item',
      tgt: target,
      tgt_type: target.includes('*') ? 'glob' : 'list',
      arg: ['kernel']
    });

    const results = {};

    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';

      let command;
      if (kernel === 'Windows') {
        command = 'Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet,Path | ConvertTo-Json';
      } else {
        command = 'ps aux --sort=-%cpu | head -100';
      }

      const shell = kernel === 'Windows' ? 'powershell' : '/bin/bash';

      try {
        const psResult = await saltClient.run({
          client: 'local',
          fun: 'cmd.run',
          tgt: minion,
          tgt_type: 'list',
          arg: [command],
          kwarg: { shell, timeout: 30 }
        });
        results[minion] = {
          kernel,
          output: psResult[minion]
        };
      } catch (err) {
        results[minion] = {
          kernel,
          error: err.message
        };
      }
    }

    res.json({
      success: true,
      processes: results
    });

  } catch (error) {
    logger.error('Failed to get detailed processes', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/processes/kill
 * Kill a process by PID
 */
router.post('/kill', async (req, res) => {
  const { targets, pid, signal = 9 } = req.body;

  if (!targets || !pid) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, pid'
    });
  }

  try {
    logger.warn(`Killing process ${pid} with signal ${signal}`, {
      user: req.username,
      targets,
      pid,
      signal
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'ps.kill_pid',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [parseInt(pid, 10)],
      kwarg: { signal: parseInt(signal, 10) }
    });

    res.json({
      success: true,
      action: 'kill',
      pid: pid,
      signal: signal,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to kill process ${pid}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/processes/pkill
 * Kill processes by name pattern
 */
router.post('/pkill', async (req, res) => {
  const { targets, pattern, signal = 9, full = false } = req.body;

  if (!targets || !pattern) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, pattern'
    });
  }

  // Basic validation - prevent dangerous patterns
  const dangerousPatterns = ['^$', '.*', '.+', '\\S+', '\\w+'];
  if (dangerousPatterns.includes(pattern)) {
    return res.status(400).json({
      success: false,
      error: 'Pattern too broad. Please be more specific.'
    });
  }

  try {
    logger.warn(`Killing processes matching pattern: ${pattern}`, {
      user: req.username,
      targets,
      pattern,
      signal
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'ps.pkill',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [pattern],
      kwarg: { signal: parseInt(signal, 10), full }
    });

    res.json({
      success: true,
      action: 'pkill',
      pattern: pattern,
      signal: signal,
      results: result
    });

  } catch (error) {
    logger.error(`Failed to pkill pattern ${pattern}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/processes/kill-windows
 * Kill a Windows process by PID or name (uses taskkill)
 */
router.post('/kill-windows', async (req, res) => {
  const { targets, pid, name, force = true } = req.body;

  if (!targets || (!pid && !name)) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets and either pid or name'
    });
  }

  try {
    let command;
    if (pid) {
      command = force
        ? `Stop-Process -Id ${pid} -Force -ErrorAction SilentlyContinue`
        : `Stop-Process -Id ${pid} -ErrorAction SilentlyContinue`;
    } else {
      command = force
        ? `Stop-Process -Name "${name}" -Force -ErrorAction SilentlyContinue`
        : `Stop-Process -Name "${name}" -ErrorAction SilentlyContinue`;
    }

    logger.warn(`Killing Windows process`, {
      user: req.username,
      targets,
      pid,
      name,
      force
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [command],
      kwarg: { shell: 'powershell', timeout: 30 }
    });

    res.json({
      success: true,
      action: 'kill-windows',
      pid: pid,
      name: name,
      results: result
    });

  } catch (error) {
    logger.error('Failed to kill Windows process', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/processes/:target/find/:name
 * Find processes by name
 */
router.get('/:target/find/:name', async (req, res) => {
  const { target, name } = req.params;

  try {
    logger.info(`Finding processes matching ${name} on ${target}`, { user: req.username });

    const result = await saltClient.run({
      client: 'local',
      fun: 'ps.pgrep',
      tgt: target,
      tgt_type: target.includes('*') ? 'glob' : 'list',
      arg: [name],
      kwarg: { full: true }
    });

    if (!result || Object.keys(result).length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No minions responded or target not found'
      });
    }

    res.json({
      success: true,
      pattern: name,
      matches: result
    });

  } catch (error) {
    logger.error(`Failed to find processes matching ${name}`, error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
