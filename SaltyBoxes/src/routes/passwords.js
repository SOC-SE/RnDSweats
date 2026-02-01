/**
 * Passwords Routes
 *
 * Password management for remote minions.
 * Supports both Linux and Windows password changes.
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

/**
 * POST /api/passwords/change
 * Change password on target minion(s)
 */
router.post('/change', async (req, res) => {
  const { targets, username, password } = req.body;

  if (!targets || !username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username, password'
    });
  }

  // Basic password validation
  if (password.length < 8) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 8 characters'
    });
  }

  // Username validation - alphanumeric and common special chars only
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(username)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid username format'
    });
  }

  try {
    logger.warn(`Changing password for user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    // First, get the OS type for each target
    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0] === '*' ? 'glob' :
                    target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'glob' ? target[0] : target;

    // Get kernel information to determine command
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

    // Process each minion based on its OS
    for (const [minion, minionGrains] of Object.entries(grains)) {
      const kernel = minionGrains?.kernel || 'Linux';

      try {
        let cmdResult;

        if (kernel === 'Windows') {
          // Windows: Use net user command
          const command = `net user "${username}" "${password}"`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: 'cmd', timeout: 30 }
          });
        } else {
          // Linux: Use chpasswd
          // Escape single quotes in password for shell safety
          const escapedPassword = password.replace(/'/g, "'\\''");
          const command = `echo '${username}:${escapedPassword}' | chpasswd`;
          cmdResult = await saltClient.run({
            client: 'local',
            fun: 'cmd.run_all',
            tgt: minion,
            arg: [command],
            kwarg: { shell: '/bin/bash', timeout: 30 }
          });
        }

        const minionResult = cmdResult[minion];
        if (minionResult?.retcode === 0) {
          results[minion] = {
            success: true,
            message: 'Password changed successfully'
          };
          successCount++;
        } else {
          results[minion] = {
            success: false,
            error: minionResult?.stderr || minionResult?.stdout || 'Unknown error'
          };
          failCount++;
        }
      } catch (err) {
        results[minion] = {
          success: false,
          error: err.message
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results,
      summary: {
        total: Object.keys(results).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to change password', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/passwords/change-linux
 * Change password on Linux minions using shadow module
 */
router.post('/change-linux', async (req, res) => {
  const { targets, username, password } = req.body;

  if (!targets || !username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username, password'
    });
  }

  try {
    logger.warn(`Changing Linux password for user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    // Escape single quotes in password
    const escapedPassword = password.replace(/'/g, "'\\''");
    const command = `echo '${username}:${escapedPassword}' | chpasswd`;

    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run_all',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [command],
      kwarg: { shell: '/bin/bash', timeout: 30 }
    });

    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, data] of Object.entries(result)) {
      if (data?.retcode === 0) {
        formattedResults[minion] = { success: true };
        successCount++;
      } else {
        formattedResults[minion] = {
          success: false,
          error: data?.stderr || data?.stdout || 'Unknown error'
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results: formattedResults,
      summary: {
        total: Object.keys(formattedResults).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to change Linux password', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/passwords/change-windows
 * Change password on Windows minions
 */
router.post('/change-windows', async (req, res) => {
  const { targets, username, password } = req.body;

  if (!targets || !username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, username, password'
    });
  }

  try {
    logger.warn(`Changing Windows password for user ${username}`, {
      user: req.username,
      targets,
      targetUser: username
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    // Use net user for broad compatibility
    const command = `net user "${username}" "${password}"`;

    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run_all',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [command],
      kwarg: { shell: 'cmd', timeout: 30 }
    });

    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, data] of Object.entries(result)) {
      if (data?.retcode === 0) {
        formattedResults[minion] = { success: true };
        successCount++;
      } else {
        formattedResults[minion] = {
          success: false,
          error: data?.stderr || data?.stdout || 'Unknown error'
        };
        failCount++;
      }
    }

    res.json({
      success: failCount === 0,
      results: formattedResults,
      summary: {
        total: Object.keys(formattedResults).length,
        success: successCount,
        failed: failCount
      }
    });

  } catch (error) {
    logger.error('Failed to change Windows password', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/passwords/bulk
 * Change password for multiple users at once
 */
router.post('/bulk', async (req, res) => {
  const { targets, users } = req.body;

  // users should be array of {username, password} objects
  if (!targets || !users || !Array.isArray(users)) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, users (array of {username, password})'
    });
  }

  try {
    logger.warn(`Bulk password change for ${users.length} users`, {
      user: req.username,
      targets,
      userCount: users.length
    });

    const results = {};

    for (const { username, password } of users) {
      if (!username || !password) continue;

      const target = Array.isArray(targets) ? targets : [targets];
      const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
      const tgt = tgtType === 'list' ? target : target[0];

      const escapedPassword = password.replace(/'/g, "'\\''");
      const command = `echo '${username}:${escapedPassword}' | chpasswd`;

      try {
        const result = await saltClient.run({
          client: 'local',
          fun: 'cmd.run_all',
          tgt: tgt,
          tgt_type: tgtType,
          arg: [command],
          kwarg: { shell: '/bin/bash', timeout: 30 }
        });

        results[username] = result;
      } catch (err) {
        results[username] = { error: err.message };
      }
    }

    res.json({
      success: true,
      results
    });

  } catch (error) {
    logger.error('Failed bulk password change', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
