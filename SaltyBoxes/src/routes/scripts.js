/**
 * Script Deployment Routes
 *
 * Handles script listing, viewing, and execution on minions.
 * This is the most critical feature - enables rapid deployment
 * of hardening and response scripts across the network.
 *
 * @module routes/scripts
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all script routes
router.use(requireAuth);

// Base directory for scripts
const SCRIPTS_BASE = path.join(process.cwd(), 'scripts');

/**
 * Validate script path to prevent directory traversal
 * @param {string} scriptPath - Relative script path
 * @returns {{valid: boolean, fullPath?: string, error?: string}}
 */
function validateScriptPath(scriptPath) {
  if (!scriptPath || typeof scriptPath !== 'string') {
    return { valid: false, error: 'Script path is required' };
  }

  // Normalize and resolve the full path
  const normalizedPath = path.normalize(scriptPath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join(SCRIPTS_BASE, normalizedPath);

  // Ensure it stays within scripts directory
  if (!fullPath.startsWith(SCRIPTS_BASE)) {
    return { valid: false, error: 'Invalid script path' };
  }

  // Check if file exists
  if (!fs.existsSync(fullPath)) {
    return { valid: false, error: 'Script not found' };
  }

  // Ensure it's a file, not a directory
  const stats = fs.statSync(fullPath);
  if (!stats.isFile()) {
    return { valid: false, error: 'Path is not a file' };
  }

  return { valid: true, fullPath };
}

/**
 * Get script metadata from file
 * @param {string} fullPath - Full path to script
 * @param {string} relativePath - Relative path for display
 * @returns {Object} Script metadata
 */
function getScriptMetadata(fullPath, relativePath) {
  const stats = fs.statSync(fullPath);
  const ext = path.extname(fullPath).toLowerCase();
  const filename = path.basename(fullPath);

  // Determine OS and shell from path and extension
  let os = 'unknown';
  let shell = 'bash';

  if (relativePath.startsWith('linux/') || relativePath.startsWith('linux\\')) {
    os = 'linux';
    shell = '/bin/bash';
  } else if (relativePath.startsWith('windows/') || relativePath.startsWith('windows\\')) {
    os = 'windows';
    shell = ext === '.ps1' ? 'powershell' : 'cmd';
  }

  // Try to extract description from first comment line
  let description = '';
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');
    for (const line of lines.slice(0, 10)) {
      const trimmed = line.trim();
      // Bash comment
      if (trimmed.startsWith('# ') && !trimmed.startsWith('#!')) {
        description = trimmed.substring(2).trim();
        break;
      }
      // PowerShell comment
      if (trimmed.startsWith('<#')) {
        const endIdx = content.indexOf('#>');
        if (endIdx > 0) {
          description = content.substring(content.indexOf('<#') + 2, endIdx).trim().split('\n')[0];
        }
        break;
      }
      // PowerShell single line comment
      if (trimmed.startsWith('# ')) {
        description = trimmed.substring(2).trim();
        break;
      }
    }
  } catch (err) {
    // Ignore read errors for description
  }

  return {
    name: filename,
    path: relativePath.replace(/\\/g, '/'),
    os,
    shell,
    extension: ext,
    size: stats.size,
    modified: stats.mtime.toISOString(),
    description: description || null
  };
}

/**
 * Recursively list scripts in a directory
 * @param {string} dir - Directory to scan
 * @param {string} base - Base path for relative paths
 * @returns {Array} List of script metadata
 */
function listScriptsInDir(dir, base = '') {
  const scripts = [];

  if (!fs.existsSync(dir)) {
    return scripts;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = base ? path.join(base, entry.name) : entry.name;

    if (entry.isDirectory()) {
      // Recurse into subdirectory
      scripts.push(...listScriptsInDir(fullPath, relativePath));
    } else if (entry.isFile()) {
      // Skip hidden files and .gitkeep
      if (entry.name.startsWith('.')) continue;

      // Only include script files
      const ext = path.extname(entry.name).toLowerCase();
      if (['.sh', '.bash', '.ps1', '.bat', '.cmd', '.py'].includes(ext)) {
        scripts.push(getScriptMetadata(fullPath, relativePath));
      }
    }
  }

  return scripts;
}

/**
 * Validate and sanitize targets
 * @param {string|string[]} targets - Target input
 * @returns {{valid: boolean, targets: string[], error?: string}}
 */
function validateTargets(targets) {
  if (!targets) {
    return { valid: false, error: 'Targets are required' };
  }

  const targetList = Array.isArray(targets) ? targets : [targets];

  if (targetList.length === 0) {
    return { valid: false, error: 'At least one target is required' };
  }

  for (const target of targetList) {
    if (typeof target !== 'string' || target.length === 0) {
      return { valid: false, error: 'Invalid target format' };
    }
    if (!/^[a-zA-Z0-9._*?[\]-]+$/.test(target)) {
      return { valid: false, error: `Invalid target: ${target}` };
    }
  }

  return { valid: true, targets: targetList };
}

// ============================================================
// Script Listing Endpoints
// ============================================================

/**
 * GET /api/scripts
 * List all available scripts
 */
router.get('/', (req, res) => {
  try {
    const scripts = listScriptsInDir(SCRIPTS_BASE);

    // Group by OS
    const grouped = {
      linux: scripts.filter(s => s.os === 'linux'),
      windows: scripts.filter(s => s.os === 'windows'),
      other: scripts.filter(s => s.os === 'unknown')
    };

    res.json({
      success: true,
      scripts,
      grouped,
      counts: {
        total: scripts.length,
        linux: grouped.linux.length,
        windows: grouped.windows.length,
        other: grouped.other.length
      }
    });
  } catch (error) {
    logger.error('Failed to list scripts', error);
    res.status(500).json({
      success: false,
      error: 'Failed to list scripts'
    });
  }
});

/**
 * GET /api/scripts/linux
 * List Linux scripts only
 */
router.get('/linux', (req, res) => {
  try {
    const linuxDir = path.join(SCRIPTS_BASE, 'linux');
    const scripts = listScriptsInDir(linuxDir, 'linux');

    res.json({
      success: true,
      os: 'linux',
      scripts,
      count: scripts.length
    });
  } catch (error) {
    logger.error('Failed to list Linux scripts', error);
    res.status(500).json({
      success: false,
      error: 'Failed to list scripts'
    });
  }
});

/**
 * GET /api/scripts/windows
 * List Windows scripts only
 */
router.get('/windows', (req, res) => {
  try {
    const windowsDir = path.join(SCRIPTS_BASE, 'windows');
    const scripts = listScriptsInDir(windowsDir, 'windows');

    res.json({
      success: true,
      os: 'windows',
      scripts,
      count: scripts.length
    });
  } catch (error) {
    logger.error('Failed to list Windows scripts', error);
    res.status(500).json({
      success: false,
      error: 'Failed to list scripts'
    });
  }
});

/**
 * GET /api/scripts/tree
 * Get scripts as a tree structure
 */
router.get('/tree', (req, res) => {
  function buildTree(dir, name = 'scripts') {
    const node = {
      name,
      type: 'directory',
      children: []
    };

    if (!fs.existsSync(dir)) {
      return node;
    }

    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        node.children.push(buildTree(fullPath, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (['.sh', '.bash', '.ps1', '.bat', '.cmd', '.py'].includes(ext)) {
          node.children.push({
            name: entry.name,
            type: 'file',
            extension: ext
          });
        }
      }
    }

    // Sort: directories first, then files
    node.children.sort((a, b) => {
      if (a.type !== b.type) {
        return a.type === 'directory' ? -1 : 1;
      }
      return a.name.localeCompare(b.name);
    });

    return node;
  }

  try {
    const tree = buildTree(SCRIPTS_BASE);
    res.json({
      success: true,
      tree
    });
  } catch (error) {
    logger.error('Failed to build script tree', error);
    res.status(500).json({
      success: false,
      error: 'Failed to build script tree'
    });
  }
});

// ============================================================
// Script Content Endpoints
// ============================================================

/**
 * GET /api/scripts/content/*
 * Get content of a specific script
 */
router.get('/content/*', (req, res) => {
  const scriptPath = req.params[0];

  const validation = validateScriptPath(scriptPath);
  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: validation.error
    });
  }

  try {
    const content = fs.readFileSync(validation.fullPath, 'utf8');
    const metadata = getScriptMetadata(validation.fullPath, scriptPath);

    res.json({
      success: true,
      script: {
        ...metadata,
        content
      }
    });
  } catch (error) {
    logger.error(`Failed to read script: ${scriptPath}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to read script'
    });
  }
});

// ============================================================
// Script Execution Endpoints
// ============================================================

/**
 * POST /api/scripts/run
 * Execute a stored script on target minions
 *
 * Body:
 *   targets: string | string[] - Target minions
 *   script: string - Relative path to script (e.g., "linux/hardening/firewall.sh")
 *   args: string[] (optional) - Arguments to pass to script
 *   timeout: number (optional) - Timeout in seconds (default: 120)
 *   shell: string (optional) - Override shell to use
 *   runas: string (optional) - User to run as
 */
router.post('/run', auditAction('script.run'), async (req, res) => {
  const {
    targets,
    script,
    args = [],
    timeout = 120,
    shell,
    runas
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate script path
  const scriptValidation = validateScriptPath(script);
  if (!scriptValidation.valid) {
    return res.status(400).json({
      success: false,
      error: scriptValidation.error
    });
  }

  // Get script metadata
  const metadata = getScriptMetadata(scriptValidation.fullPath, script);

  // Read script content
  let scriptContent;
  try {
    scriptContent = fs.readFileSync(scriptValidation.fullPath, 'utf8');
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to read script'
    });
  }

  const timeoutSec = Math.min(Math.max(parseInt(timeout, 10) || 120, 1), 600);
  const startTime = Date.now();

  // Determine shell to use
  const effectiveShell = shell || metadata.shell;

  try {
    logger.info(`Executing script ${script} on ${targetValidation.targets.join(', ')}`);

    // Execute script content using cmd.run
    // We use scriptContent instead of script because we have the content locally
    // and don't want to require serving it over HTTP
    const result = await saltClient.scriptContent(
      targetValidation.targets,
      scriptContent,
      {
        shell: effectiveShell,
        args: args.join(' '),
        timeout: timeoutSec,
        runas
      }
    );

    const executionTime = Date.now() - startTime;

    // Format results
    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, output] of Object.entries(result)) {
      const isError = typeof output === 'string' &&
        (output.includes('Minion did not return') ||
         output.includes('No minions matched') ||
         output.startsWith('ERROR:'));

      if (isError) {
        failCount++;
        formattedResults[minion] = {
          success: false,
          output,
          error: true
        };
      } else {
        successCount++;
        formattedResults[minion] = {
          success: true,
          output
        };
      }
    }

    res.json({
      success: true,
      script: metadata.path,
      targets: targetValidation.targets,
      shell: effectiveShell,
      results: formattedResults,
      summary: {
        total: Object.keys(result).length,
        success: successCount,
        failed: failCount
      },
      execution_time_ms: executionTime
    });
  } catch (error) {
    logger.error(`Script execution failed: ${script}`, error);
    res.status(500).json({
      success: false,
      error: 'Script execution failed',
      details: error.message
    });
  }
});

/**
 * POST /api/scripts/run-inline
 * Execute inline script content on target minions
 *
 * Body:
 *   targets: string | string[] - Target minions
 *   content: string - Script content to execute
 *   shell: string - Shell to use (bash, powershell, cmd)
 *   args: string[] (optional) - Arguments
 *   timeout: number (optional) - Timeout in seconds
 *   runas: string (optional) - User to run as
 */
router.post('/run-inline', auditAction('script.run_inline'), async (req, res) => {
  const {
    targets,
    content,
    shell = '/bin/bash',
    args = [],
    timeout = 120,
    runas
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate content
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Script content is required'
    });
  }

  const timeoutSec = Math.min(Math.max(parseInt(timeout, 10) || 120, 1), 600);
  const startTime = Date.now();

  try {
    logger.debug(`Executing inline script on ${targetValidation.targets.join(', ')}`);

    const result = await saltClient.script(
      targetValidation.targets,
      content,
      {
        shell,
        args: args.join(' '),
        timeout: timeoutSec,
        runas
      }
    );

    const executionTime = Date.now() - startTime;

    // Format results
    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, output] of Object.entries(result)) {
      const isError = typeof output === 'string' &&
        (output.includes('Minion did not return') ||
         output.includes('No minions matched') ||
         output.startsWith('ERROR:'));

      if (isError) {
        failCount++;
        formattedResults[minion] = {
          success: false,
          output,
          error: true
        };
      } else {
        successCount++;
        formattedResults[minion] = {
          success: true,
          output
        };
      }
    }

    res.json({
      success: true,
      type: 'inline',
      targets: targetValidation.targets,
      shell,
      results: formattedResults,
      summary: {
        total: Object.keys(result).length,
        success: successCount,
        failed: failCount
      },
      execution_time_ms: executionTime
    });
  } catch (error) {
    logger.error('Inline script execution failed', error);
    res.status(500).json({
      success: false,
      error: 'Script execution failed',
      details: error.message
    });
  }
});

/**
 * POST /api/scripts/run-async
 * Execute script asynchronously (returns job ID)
 *
 * Body:
 *   targets: string | string[] - Target minions
 *   script: string - Relative path to script
 *   args: string[] (optional) - Arguments
 *   timeout: number (optional) - Timeout in seconds
 */
router.post('/run-async', auditAction('script.run_async'), async (req, res) => {
  const {
    targets,
    script,
    args = [],
    timeout = 120
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate script path
  const scriptValidation = validateScriptPath(script);
  if (!scriptValidation.valid) {
    return res.status(400).json({
      success: false,
      error: scriptValidation.error
    });
  }

  // Get script metadata and content
  const metadata = getScriptMetadata(scriptValidation.fullPath, script);
  let scriptContent;
  try {
    scriptContent = fs.readFileSync(scriptValidation.fullPath, 'utf8');
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to read script'
    });
  }

  try {
    // For async execution, we need to use Salt's local_async client
    // We'll create a temporary approach using cmd.run with the content
    const jid = await saltClient.runAsync({
      client: 'local_async',
      fun: 'cmd.run',
      tgt: targetValidation.targets,
      tgt_type: targetValidation.targets.length > 1 ? 'list' : 'glob',
      arg: [scriptContent],
      kwarg: {
        shell: metadata.shell,
        timeout: Math.min(parseInt(timeout, 10) || 120, 600)
      }
    });

    logger.info(`Async script submitted: ${jid} (${script})`);

    res.json({
      success: true,
      jid,
      message: 'Script submitted asynchronously',
      script: metadata.path,
      targets: targetValidation.targets
    });
  } catch (error) {
    logger.error('Async script submission failed', error);
    res.status(500).json({
      success: false,
      error: 'Failed to submit async script',
      details: error.message
    });
  }
});

// ============================================================
// Script Management Endpoints
// ============================================================

/**
 * POST /api/scripts/upload
 * Upload a new script
 *
 * Body:
 *   path: string - Relative path where to save (e.g., "linux/hardening/myscript.sh")
 *   content: string - Script content
 *   overwrite: boolean (optional) - Allow overwriting existing scripts
 */
router.post('/upload', auditAction('script.upload'), (req, res) => {
  const { path: scriptPath, content, overwrite = false } = req.body;

  if (!scriptPath || typeof scriptPath !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Script path is required'
    });
  }

  if (!content || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Script content is required'
    });
  }

  // Validate path doesn't escape scripts directory
  const normalizedPath = path.normalize(scriptPath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join(SCRIPTS_BASE, normalizedPath);

  if (!fullPath.startsWith(SCRIPTS_BASE)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid script path'
    });
  }

  // Check if file exists and overwrite flag
  if (fs.existsSync(fullPath) && !overwrite) {
    return res.status(409).json({
      success: false,
      error: 'Script already exists. Set overwrite=true to replace.'
    });
  }

  // Ensure directory exists
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  try {
    fs.writeFileSync(fullPath, content, 'utf8');

    logger.info(`Script uploaded: ${scriptPath}`);

    const metadata = getScriptMetadata(fullPath, normalizedPath);

    res.json({
      success: true,
      message: 'Script uploaded successfully',
      script: metadata
    });
  } catch (error) {
    logger.error(`Failed to upload script: ${scriptPath}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload script'
    });
  }
});

/**
 * DELETE /api/scripts/content/*
 * Delete a script
 */
router.delete('/content/*', auditAction('script.delete'), (req, res) => {
  const scriptPath = req.params[0];

  const validation = validateScriptPath(scriptPath);
  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: validation.error
    });
  }

  try {
    fs.unlinkSync(validation.fullPath);

    logger.info(`Script deleted: ${scriptPath}`);

    res.json({
      success: true,
      message: 'Script deleted successfully',
      path: scriptPath
    });
  } catch (error) {
    logger.error(`Failed to delete script: ${scriptPath}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete script'
    });
  }
});

module.exports = router;
