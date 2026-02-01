/**
 * States Routes
 *
 * Salt state management - apply, test, and list Salt states.
 * Supports states stored on the Salt Master or inline YAML.
 */

const express = require('express');
const router = express.Router();
const fs = require('fs').promises;
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

// States directory (local states, if any)
const STATES_DIR = path.join(__dirname, '..', '..', 'states');

/**
 * GET /api/states
 * List available states (both local and on Salt Master)
 */
router.get('/', async (req, res) => {
  try {
    const states = {
      local: [],
      salt: []
    };

    // List local states
    try {
      const localStates = await listLocalStates(STATES_DIR);
      states.local = localStates;
    } catch (err) {
      logger.debug('No local states found');
    }

    // Try to list states from Salt Master file_roots
    try {
      // This uses cp.list_states which lists states available on the master
      const saltStates = await saltClient.run({
        client: 'runner',
        fun: 'state.orchestrate_show_sls',
        kwarg: {}
      });
      // This is limited - ideally we'd have access to list states
    } catch (err) {
      // May not have access
      logger.debug('Could not list Salt Master states');
    }

    res.json({
      success: true,
      states
    });

  } catch (error) {
    logger.error('Failed to list states', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/states/local
 * List local states stored on Salt-GUI server
 */
router.get('/local', async (req, res) => {
  try {
    const states = await listLocalStates(STATES_DIR);

    res.json({
      success: true,
      states
    });

  } catch (error) {
    logger.error('Failed to list local states', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/states/local/:path
 * Get content of a local state file
 */
router.get('/local/*', async (req, res) => {
  const statePath = req.params[0];

  // Prevent path traversal
  if (statePath.includes('..') || statePath.startsWith('/')) {
    return res.status(400).json({
      success: false,
      error: 'Invalid state path'
    });
  }

  try {
    const fullPath = path.join(STATES_DIR, statePath);

    // Verify path is within states directory
    const resolvedPath = path.resolve(fullPath);
    if (!resolvedPath.startsWith(path.resolve(STATES_DIR))) {
      return res.status(400).json({
        success: false,
        error: 'Invalid state path'
      });
    }

    const content = await fs.readFile(fullPath, 'utf8');
    const stat = await fs.stat(fullPath);

    res.json({
      success: true,
      state: {
        path: statePath,
        name: path.basename(statePath),
        content,
        size: stat.size,
        modified: stat.mtime
      }
    });

  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({
        success: false,
        error: 'State file not found'
      });
    }
    logger.error('Failed to read state file', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/states/apply
 * Apply a Salt state to target minions
 */
router.post('/apply', async (req, res) => {
  const { targets, state, test = false, timeout = 600 } = req.body;

  if (!targets || !state) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, state'
    });
  }

  try {
    logger.info(`Applying state ${state} (test=${test})`, {
      user: req.username,
      targets,
      state,
      test
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const startTime = Date.now();

    const result = await saltClient.run({
      client: 'local',
      fun: 'state.apply',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [state],
      kwarg: test ? { test: true } : {},
      timeout: timeout * 1000
    });

    const executionTime = Date.now() - startTime;

    // Process results to extract summary
    const summary = {
      total: 0,
      success: 0,
      failed: 0,
      changed: 0
    };

    const formattedResults = {};

    for (const [minion, stateResult] of Object.entries(result || {})) {
      summary.total++;

      if (typeof stateResult === 'string') {
        // Error message
        formattedResults[minion] = {
          error: true,
          message: stateResult
        };
        summary.failed++;
        continue;
      }

      let minionSuccess = true;
      let minionChanged = 0;
      const states = [];

      for (const [stateId, stateData] of Object.entries(stateResult || {})) {
        const stateName = stateData?.name || stateId;
        const result = stateData?.result;
        const changes = stateData?.changes || {};
        const comment = stateData?.comment || '';

        if (result === false) {
          minionSuccess = false;
        }
        if (Object.keys(changes).length > 0) {
          minionChanged++;
        }

        states.push({
          id: stateId,
          name: stateName,
          result,
          changes: Object.keys(changes).length > 0 ? changes : null,
          comment
        });
      }

      formattedResults[minion] = {
        error: false,
        success: minionSuccess,
        changed: minionChanged,
        states
      };

      if (minionSuccess) {
        summary.success++;
      } else {
        summary.failed++;
      }
      summary.changed += minionChanged;
    }

    res.json({
      success: summary.failed === 0,
      state,
      test,
      results: formattedResults,
      summary,
      execution_time_ms: executionTime
    });

  } catch (error) {
    logger.error('Failed to apply state', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/states/apply-inline
 * Apply inline YAML state content
 */
router.post('/apply-inline', async (req, res) => {
  const { targets, content, test = false, timeout = 600 } = req.body;

  if (!targets || !content) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, content'
    });
  }

  try {
    logger.info('Applying inline state', {
      user: req.username,
      targets,
      contentLength: content.length,
      test
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const startTime = Date.now();

    const result = await saltClient.run({
      client: 'local',
      fun: 'state.template_str',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [content],
      kwarg: test ? { test: true } : {},
      timeout: timeout * 1000
    });

    const executionTime = Date.now() - startTime;

    res.json({
      success: true,
      test,
      results: result,
      execution_time_ms: executionTime
    });

  } catch (error) {
    logger.error('Failed to apply inline state', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/states/highstate
 * Apply highstate (all states for minion)
 */
router.post('/highstate', async (req, res) => {
  const { targets, test = false, timeout = 1200 } = req.body;

  if (!targets) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: targets'
    });
  }

  try {
    logger.info('Applying highstate', {
      user: req.username,
      targets,
      test
    });

    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const startTime = Date.now();

    const result = await saltClient.run({
      client: 'local',
      fun: 'state.highstate',
      tgt: tgt,
      tgt_type: tgtType,
      kwarg: test ? { test: true } : {},
      timeout: timeout * 1000
    });

    const executionTime = Date.now() - startTime;

    res.json({
      success: true,
      test,
      results: result,
      execution_time_ms: executionTime
    });

  } catch (error) {
    logger.error('Failed to apply highstate', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/states/show
 * Show what a state would do (preview)
 */
router.post('/show', async (req, res) => {
  const { targets, state } = req.body;

  if (!targets || !state) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: targets, state'
    });
  }

  try {
    const target = Array.isArray(targets) ? targets : [targets];
    const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
    const tgt = tgtType === 'list' ? target : target[0];

    const result = await saltClient.run({
      client: 'local',
      fun: 'state.show_sls',
      tgt: tgt,
      tgt_type: tgtType,
      arg: [state]
    });

    res.json({
      success: true,
      state,
      preview: result
    });

  } catch (error) {
    logger.error('Failed to show state', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Recursively list state files in a directory
 */
async function listLocalStates(dir, basePath = '') {
  const states = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = basePath ? `${basePath}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        const subStates = await listLocalStates(fullPath, relativePath);
        states.push({
          type: 'directory',
          name: entry.name,
          path: relativePath,
          children: subStates
        });
      } else if (entry.name.endsWith('.sls') || entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        const stat = await fs.stat(fullPath);
        states.push({
          type: 'file',
          name: entry.name,
          path: relativePath,
          size: stat.size,
          modified: stat.mtime
        });
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }

  return states;
}

module.exports = router;
