/**
 * Playbooks Routes
 *
 * Automation playbooks for enumeration, defense, and incident response.
 * Playbooks define multi-step sequences of scripts, commands, and states.
 */

const express = require('express');
const router = express.Router();
const fs = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');
const { requireAuth } = require('../middleware/auth');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');

// All routes require authentication
router.use(requireAuth);

// Playbooks directory
const PLAYBOOKS_DIR = path.join(__dirname, '..', '..', 'playbooks');
const SCRIPTS_DIR = path.join(__dirname, '..', '..', 'scripts');

/**
 * GET /api/playbooks
 * List all playbooks
 */
router.get('/', async (req, res) => {
  try {
    const playbooks = await listPlaybooks(PLAYBOOKS_DIR);

    res.json({
      success: true,
      playbooks
    });

  } catch (error) {
    logger.error('Failed to list playbooks', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/playbooks/tree
 * Get playbooks as a tree structure (matching scripts pattern)
 */
router.get('/tree', async (req, res) => {
  try {
    const tree = await buildPlaybookTree(PLAYBOOKS_DIR);

    res.json({
      success: true,
      tree: {
        type: 'directory',
        name: 'playbooks',
        children: tree
      }
    });

  } catch (error) {
    logger.error('Failed to get playbook tree', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/playbooks/content/:path
 * Get playbook content and metadata
 */
router.get('/content/*', async (req, res) => {
  const playbookPath = req.params[0];

  // Prevent path traversal
  if (playbookPath.includes('..') || playbookPath.startsWith('/')) {
    return res.status(400).json({
      success: false,
      error: 'Invalid playbook path'
    });
  }

  try {
    const fullPath = path.join(PLAYBOOKS_DIR, playbookPath);

    // Verify path is within playbooks directory
    const resolvedPath = path.resolve(fullPath);
    if (!resolvedPath.startsWith(path.resolve(PLAYBOOKS_DIR))) {
      return res.status(400).json({
        success: false,
        error: 'Invalid playbook path'
      });
    }

    const content = await fs.readFile(fullPath, 'utf8');
    const stat = await fs.stat(fullPath);

    // Parse YAML content
    let parsed;
    try {
      parsed = yaml.load(content);
    } catch (yamlError) {
      return res.status(400).json({
        success: false,
        error: 'Invalid playbook YAML: ' + yamlError.message
      });
    }

    // Determine OS from path
    const os = playbookPath.startsWith('linux/') ? 'linux' :
               playbookPath.startsWith('windows/') ? 'windows' : 'cross-platform';

    res.json({
      success: true,
      playbook: {
        path: playbookPath,
        name: parsed.name || path.basename(playbookPath, path.extname(playbookPath)),
        description: parsed.description || '',
        os,
        steps: parsed.steps || [],
        content,
        size: stat.size,
        modified: stat.mtime
      }
    });

  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({
        success: false,
        error: 'Playbook not found'
      });
    }
    logger.error('Failed to read playbook', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/playbooks/run
 * Execute a playbook
 */
router.post('/run', async (req, res) => {
  const { playbook, targets: targetOverride, timeout = 600 } = req.body;

  if (!playbook) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: playbook'
    });
  }

  try {
    // Load playbook
    const fullPath = path.join(PLAYBOOKS_DIR, playbook);

    // Verify path is within playbooks directory
    const resolvedPath = path.resolve(fullPath);
    if (!resolvedPath.startsWith(path.resolve(PLAYBOOKS_DIR))) {
      return res.status(400).json({
        success: false,
        error: 'Invalid playbook path'
      });
    }

    const content = await fs.readFile(fullPath, 'utf8');
    const playbookData = yaml.load(content);

    if (!playbookData.steps || playbookData.steps.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Playbook has no steps'
      });
    }

    logger.info(`Running playbook: ${playbook}`, {
      user: req.username,
      steps: playbookData.steps.length,
      targetOverride
    });

    const startTime = Date.now();
    const results = [];
    let overallSuccess = true;

    // Execute each step in sequence
    for (let i = 0; i < playbookData.steps.length; i++) {
      const step = playbookData.steps[i];
      const stepResult = {
        step: i + 1,
        name: step.name,
        type: step.type,
        success: false,
        output: null
      };

      // Determine targets for this step
      let targets = targetOverride || step.target || '*';

      try {
        const stepStartTime = Date.now();

        if (step.type === 'command') {
          // Execute command
          const target = Array.isArray(targets) ? targets : [targets];
          const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
          const tgt = tgtType === 'list' ? target : target[0];

          // Normalize shell path - Salt needs full path
          let shell = step.shell;
          if (shell === 'bash') shell = '/bin/bash';
          else if (shell === 'sh') shell = '/bin/sh';
          else if (shell === 'zsh') shell = '/bin/zsh';
          else if (shell === 'cmd') shell = 'cmd.exe';

          const result = await saltClient.run({
            client: 'local',
            fun: 'cmd.run',
            tgt: tgt,
            tgt_type: tgtType,
            arg: [step.command],
            kwarg: shell ? { shell } : {},
            timeout: (step.timeout || 60) * 1000
          });

          stepResult.output = result;
          stepResult.success = true;

        } else if (step.type === 'script') {
          // Execute script from scripts directory
          const scriptPath = path.join(SCRIPTS_DIR, step.script);

          // Verify script exists
          await fs.access(scriptPath);
          const scriptContent = await fs.readFile(scriptPath, 'utf8');

          // Determine shell from script
          const isWindows = step.script.startsWith('windows/');
          const shell = isWindows ? 'powershell' : '/bin/bash';

          const target = Array.isArray(targets) ? targets : [targets];
          const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
          const tgt = tgtType === 'list' ? target : target[0];

          const args = step.args || [];

          const result = await saltClient.run({
            client: 'local',
            fun: 'cmd.run',
            tgt: tgt,
            tgt_type: tgtType,
            arg: [scriptContent + (args.length > 0 ? ' ' + args.join(' ') : '')],
            kwarg: { shell },
            timeout: (step.timeout || 120) * 1000
          });

          stepResult.output = result;
          stepResult.success = true;

        } else if (step.type === 'state') {
          // Apply Salt state
          const target = Array.isArray(targets) ? targets : [targets];
          const tgtType = target.length === 1 && target[0].includes('*') ? 'glob' : 'list';
          const tgt = tgtType === 'list' ? target : target[0];

          const result = await saltClient.run({
            client: 'local',
            fun: 'state.apply',
            tgt: tgt,
            tgt_type: tgtType,
            arg: [step.state],
            kwarg: step.test ? { test: true } : {},
            timeout: (step.timeout || 300) * 1000
          });

          stepResult.output = result;
          stepResult.success = true;

        } else {
          stepResult.output = `Unknown step type: ${step.type}`;
          stepResult.success = false;
        }

        stepResult.duration_ms = Date.now() - stepStartTime;

      } catch (stepError) {
        stepResult.output = stepError.message;
        stepResult.success = false;
        stepResult.duration_ms = 0;
      }

      results.push(stepResult);

      // Handle failure based on on_failure setting
      if (!stepResult.success) {
        overallSuccess = false;
        if (step.on_failure === 'stop') {
          break;
        }
        // Default is 'continue'
      }
    }

    const executionTime = Date.now() - startTime;

    res.json({
      success: overallSuccess,
      playbook,
      results,
      summary: {
        total: results.length,
        success: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length
      },
      execution_time_ms: executionTime
    });

  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({
        success: false,
        error: 'Playbook not found'
      });
    }
    logger.error('Failed to run playbook', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Recursively list playbook files
 */
async function listPlaybooks(dir, basePath = '') {
  const playbooks = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = basePath ? `${basePath}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        const subPlaybooks = await listPlaybooks(fullPath, relativePath);
        playbooks.push(...subPlaybooks);
      } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = yaml.load(content);
          const stat = await fs.stat(fullPath);

          playbooks.push({
            path: relativePath,
            name: parsed.name || entry.name.replace(/\.ya?ml$/, ''),
            description: parsed.description || '',
            steps: (parsed.steps || []).length,
            size: stat.size,
            modified: stat.mtime
          });
        } catch (parseError) {
          // Skip invalid YAML files
          logger.debug(`Skipping invalid playbook: ${relativePath}`);
        }
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw err;
    }
  }

  return playbooks;
}

/**
 * Build playbook tree structure (matching scripts pattern)
 */
async function buildPlaybookTree(dir, basePath = '') {
  const tree = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = basePath ? `${basePath}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        const children = await buildPlaybookTree(fullPath, relativePath);
        tree.push({
          type: 'directory',
          name: entry.name,
          path: relativePath,
          children
        });
      } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        const stat = await fs.stat(fullPath);
        tree.push({
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

  return tree;
}

module.exports = router;
