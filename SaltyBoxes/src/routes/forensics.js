/**
 * Forensics Routes
 *
 * Provides forensic collection, artifact browsing, analysis, findings,
 * timeline, and metadata endpoints for incident response.
 *
 * @module routes/forensics
 */

const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

const MINION_CACHE_BASE = '/var/cache/salt/master/minions';

/**
 * Get the local path for a cp.push'd artifact, or null if not available.
 */
function getLocalArtifactPath(minion, artifactPath) {
  const rel = artifactPath.replace(/^\//, '');
  const full = path.join(MINION_CACHE_BASE, minion, 'files', rel);
  if (!path.resolve(full).startsWith(MINION_CACHE_BASE)) return null;
  try {
    if (fs.existsSync(full)) return full;
  } catch {}
  return null;
}

/**
 * Promise wrapper around execFile for local tar operations.
 */
function execLocal(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024, timeout: 60000, ...opts }, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve({ stdout, stderr });
    });
  });
}

router.use(requireAuth);

// In-memory job tracking
const forensicJobs = new Map();

function generateJobId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

// ============================================================
// Collection Endpoints
// ============================================================

/**
 * POST /api/forensics/collect
 * Standard forensic collection
 */
router.post('/collect', auditAction('forensics.collect'), async (req, res) => {
  const { targets, level = 'standard' } = req.body;
  const timeout = req.body.timeout || (level === 'comprehensive' ? 900 : 300);

  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level, targets, created: new Date().toISOString(), results: null });

  // Run async
  (async () => {
    try {
      const collectScript = buildCollectScript(level);
      const result = await saltClient.cmdScript(targets, collectScript, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Collection started' });
});

/**
 * POST /api/forensics/quick-collect
 * Quick forensic collection (minimal)
 */
router.post('/quick-collect', auditAction('forensics.quick_collect'), async (req, res) => {
  const { targets, timeout = 120 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'quick', targets, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      const script = buildCollectScript('quick');
      const result = await saltClient.cmdScript(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Quick collection started' });
});

/**
 * POST /api/forensics/advanced
 * Advanced forensic collection
 */
router.post('/advanced', auditAction('forensics.advanced'), async (req, res) => {
  const { targets, timeout = 600 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'advanced', targets, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      const script = buildCollectScript('advanced');
      const result = await saltClient.cmdScript(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Advanced collection started' });
});

/**
 * POST /api/forensics/comprehensive
 * Comprehensive forensic collection with all options
 *
 * When skip_scans=true, collection runs fast (~30s) and returns immediately.
 * Security scans can then be run separately via /api/forensics/scan for progressive display.
 */
router.post('/comprehensive', auditAction('forensics.comprehensive'), async (req, res) => {
  const { targets, memory_dump = false, volatility = false, quick_mode = false, skip_logs = false, skip_scans = false, auto_install = true, timeout = 900 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  const opts = { memory_dump, volatility, quick_mode, skip_logs, skip_scans, auto_install };
  // Use shorter timeout when skipping scans (collection only takes ~30-60s)
  // But if memory dump/volatility is enabled, allow more time
  const effectiveTimeout = skip_scans && !memory_dump ? Math.min(timeout, 180) : timeout;
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'comprehensive', targets, options: opts, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      // Auto-install forensic tools before scanning (default: on)
      let installResults = null;
      if (auto_install) {
        try {
          const installScript = buildToolInstallScript();
          installResults = await saltClient.cmdScript(targets, installScript, { shell: '/bin/bash', timeout: 300 });
          logger.info('Forensic tool install completed');
        } catch (installErr) {
          logger.warn(`Forensic tool install warning: ${installErr.message}`);
        }
      }
      const script = buildCollectScript('comprehensive', opts);
      const result = await saltClient.cmdScript(targets, script, { shell: '/bin/bash', timeout: effectiveTimeout });

      // Extract tarball paths from results for each minion
      const tarballPaths = {};
      for (const [minion, output] of Object.entries(result)) {
        if (typeof output === 'string') {
          // Look for [TARBALL] marker in output
          const tarballMatch = output.match(/\[TARBALL\] (.+\.tar\.gz)/);
          if (tarballMatch) {
            tarballPaths[minion] = tarballMatch[1].trim();
          }
        }
      }

      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result, install_results: installResults, tarball_paths: tarballPaths });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Comprehensive collection started' });
});

/**
 * GET /api/forensics/status/:id
 * Get job status
 */
router.get('/status/:id', async (req, res) => {
  const job = forensicJobs.get(req.params.id);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }
  res.json({ success: true, job });
});

/**
 * GET /api/forensics/jobs
 * List all forensic jobs
 */
router.get('/jobs', async (req, res) => {
  const jobs = Array.from(forensicJobs.values()).sort((a, b) => new Date(b.created) - new Date(a.created));
  res.json({ success: true, jobs });
});

/**
 * POST /api/forensics/install-tools
 * Install forensic tools on targets (standalone or before collection)
 */
router.post('/install-tools', auditAction('forensics.install_tools'), async (req, res) => {
  const { targets, timeout = 300 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    type: 'install-tools',
    targets,
    created: new Date().toISOString(),
    results: null
  });

  (async () => {
    try {
      const script = buildToolInstallScript();
      const result = await saltClient.cmdScript(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
      logger.info(`Forensic tools install job ${jobId} completed`);
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
      logger.error(`Forensic tools install job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Tool installation started' });
});

/**
 * POST /api/forensics/scan
 * Run security scans separately (Phase 2 - slow scanners)
 * This allows collection results to be displayed quickly while scans run in background
 *
 * The scan script automatically finds and updates the most recent collection tarball
 * for each minion, creating a single combined artifact with both collection and scan results.
 */
router.post('/scan', auditAction('forensics.scan'), async (req, res) => {
  const { targets, memory_dump = false, timeout = 600 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    type: 'scan',
    targets,
    options: { memory_dump },
    created: new Date().toISOString(),
    results: null,
    scan_progress: {}
  });

  (async () => {
    try {
      const script = buildScanScript({ memory_dump });
      const result = await saltClient.cmdScript(targets, script, { shell: '/bin/bash', timeout });

      // Parse scan results for summary
      const scanSummary = {};
      for (const [minion, output] of Object.entries(result)) {
        if (typeof output === 'string') {
          const summary = {};
          // Extract [SCAN_RESULT] lines
          const resultMatches = output.match(/\[SCAN_RESULT\] (\w+)=(.+)/g) || [];
          for (const match of resultMatches) {
            const m = match.match(/\[SCAN_RESULT\] (\w+)=(.+)/);
            if (m) summary[m[1]] = m[2].trim();
          }
          scanSummary[minion] = summary;
        }
      }

      forensicJobs.set(jobId, {
        ...forensicJobs.get(jobId),
        status: 'completed',
        results: result,
        scan_summary: scanSummary
      });
      logger.info(`Security scan job ${jobId} completed`);
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
      logger.error(`Security scan job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Security scan started' });
});

// ============================================================
// Artifact Endpoints
// ============================================================

/**
 * GET /api/forensics/collections
 * List all forensic collections across targets
 */
router.get('/collections', async (req, res) => {
  try {
    // Return only tarball collections, not loose files
    const result = await saltClient.cmd('*', 'find /tmp/forensics/ -maxdepth 1 -name "*.tar.gz" -type f -printf "%f\\n" 2>/dev/null | sort -r || echo ""', { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, collections: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/artifacts/:target
 * List artifacts on a specific target
 */
router.get('/artifacts/:target', async (req, res) => {
  const { target } = req.params;
  try {
    const result = await saltClient.cmd(target, 'find /tmp/forensics/ -name "*.tar.gz" -o -name "*.log" -o -name "*.json" 2>/dev/null | head -100 || echo "No artifacts"', { shell: '/bin/bash', timeout: 30 });
    const artifacts = {};
    for (const [minion, output] of Object.entries(result)) {
      if (typeof output === 'string' && output !== 'No artifacts') {
        artifacts[minion] = output.split('\n').filter(f => f.trim()).map(f => ({ path: f.trim() }));
      } else {
        artifacts[minion] = [];
      }
    }
    res.json({ success: true, artifacts });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact-contents
 * List contents of a tarball artifact
 */
router.post('/artifact-contents', async (req, res) => {
  const { target, artifact_path } = req.body;
  if (!target || !artifact_path) {
    return res.status(400).json({ success: false, error: 'Target and artifact_path required' });
  }
  try {
    const localPath = getLocalArtifactPath(target, artifact_path);
    if (localPath) {
      const { stdout } = await execLocal('tar', ['tzf', localPath]);
      const fileList = stdout.split('\n').filter(f => f.trim()).slice(0, 500);
      res.json({ success: true, files: { [target]: fileList }, local: true });
      return;
    }
    const result = await saltClient.cmd(target, `tar tzf '${artifact_path.replace(/'/g, "\\'")}' 2>/dev/null | head -500`, { shell: '/bin/bash', timeout: 60 });
    const files = {};
    for (const [minion, output] of Object.entries(result)) {
      files[minion] = typeof output === 'string' ? output.split('\n').filter(f => f.trim()) : [];
    }
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact-file
 * Extract and view a single file from a tarball
 */
router.post('/artifact-file', async (req, res) => {
  const { target, artifact_path, file_path } = req.body;
  if (!target || !artifact_path || !file_path) {
    return res.status(400).json({ success: false, error: 'Target, artifact_path, and file_path required' });
  }
  try {
    const localPath = getLocalArtifactPath(target, artifact_path);
    if (localPath) {
      const { stdout } = await execLocal('tar', ['xzf', localPath, '-O', file_path]);
      const truncated = stdout.split('\n').slice(0, 2000).join('\n');
      res.json({ success: true, content: { [target]: truncated }, local: true });
      return;
    }
    const result = await saltClient.cmd(target, `tar xzf '${artifact_path.replace(/'/g, "\\'")}' -O '${file_path.replace(/'/g, "\\'")}' 2>/dev/null | head -2000`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/artifact/:target/content
 * Alternative: list tarball contents for a target
 */
router.get('/artifact/:target/content', async (req, res) => {
  const { target } = req.params;
  const { path: artifactPath } = req.query;
  if (!artifactPath) {
    return res.status(400).json({ success: false, error: 'path query param required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar tzf '${artifactPath.replace(/'/g, "\\'")}' 2>/dev/null | head -500`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, files: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact/:target/extract
 * Extract a specific file from a tarball
 */
router.post('/artifact/:target/extract', async (req, res) => {
  const { target } = req.params;
  const { artifact_path, file_path } = req.body;
  if (!artifact_path || !file_path) {
    return res.status(400).json({ success: false, error: 'artifact_path and file_path required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar xzf '${artifact_path.replace(/'/g, "\\'")}' -O '${file_path.replace(/'/g, "\\'")}' 2>/dev/null | head -2000`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/read-file
 * Read a plain file from /tmp/forensics/ on a minion
 */
router.post('/read-file', async (req, res) => {
  const { target, filename } = req.body;
  if (!target || !filename) {
    return res.status(400).json({ success: false, error: 'Target and filename required' });
  }
  // Sanitize: only allow simple filenames, no path traversal
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safe) {
    return res.status(400).json({ success: false, error: 'Invalid filename' });
  }
  try {
    const result = await saltClient.cmd(target, `head -2000 '/tmp/forensics/${safe}' 2>/dev/null || echo "File not found"`, { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/retrieve
 * Retrieve artifact to Salt master via cp.push
 */
router.post('/retrieve', auditAction('forensics.retrieve'), async (req, res) => {
  const { target, artifact_path } = req.body;
  if (!target || !artifact_path) {
    return res.status(400).json({ success: false, error: 'Target and artifact_path required' });
  }
  try {
    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cp.push',
      arg: [artifact_path]
    });
    res.json({ success: true, result, local: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/cleanup
 * Clean up old forensic artifacts
 */
router.post('/cleanup', auditAction('forensics.cleanup'), async (req, res) => {
  const { targets = '*', age_hours = 24 } = req.body;
  try {
    const result = await saltClient.cmd(targets, `find /tmp/forensics/ -type f -mmin +${age_hours * 60} -delete 2>/dev/null; echo "Cleanup complete"`, { shell: '/bin/bash', timeout: 60 });

    // Also clean up local cached copies from cp.push
    let localCleaned = 0;
    try {
      const minionDirs = fs.readdirSync(MINION_CACHE_BASE);
      const ageMs = age_hours * 3600 * 1000;
      const now = Date.now();
      for (const minion of minionDirs) {
        const forensicsDir = path.join(MINION_CACHE_BASE, minion, 'files', 'tmp', 'forensics');
        if (!fs.existsSync(forensicsDir)) continue;
        const files = fs.readdirSync(forensicsDir);
        for (const file of files) {
          const full = path.join(forensicsDir, file);
          try {
            const stat = fs.statSync(full);
            if (stat.isFile() && (now - stat.mtimeMs) > ageMs) {
              fs.unlinkSync(full);
              localCleaned++;
            }
          } catch (fileErr) {
            logger.warn(`Local cache cleanup file error: ${full}: ${fileErr.message}`);
          }
        }
      }
    } catch (e) {
      logger.warn(`Local cache cleanup error: ${e.message}`);
    }

    res.json({ success: true, result, local_cleaned: localCleaned });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Analysis Endpoints
// ============================================================

/**
 * POST /api/forensics/analyze
 * Live 16-category forensic analysis
 */
router.post('/analyze', auditAction('forensics.analyze'), async (req, res) => {
  const { target, timeout = 300 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const script = buildAnalysisScript();
    const result = await saltClient.cmdScript(target, script, { shell: '/bin/bash', timeout });

    // Parse results into findings
    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      findings[minion] = parseAnalysisOutput(output);
    }

    res.json({ success: true, findings });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/analysis
 * Targeted analysis by type
 */
router.post('/analysis', auditAction('forensics.analysis'), async (req, res) => {
  const { target, tarball_path, types = [], timeout = 300 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const analysisTypes = types.length > 0 ? types : ['rootkit', 'persistence', 'network', 'users', 'processes'];
    const script = buildTargetedAnalysisScript(analysisTypes, tarball_path);
    const result = await saltClient.cmdScript(target, script, { shell: '/bin/bash', timeout });

    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      findings[minion] = parseAnalysisOutput(output);
    }

    res.json({ success: true, findings, types: analysisTypes });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Findings, Timeline, Metadata Endpoints
// ============================================================

/**
 * GET /api/forensics/findings/:target
 * Get findings for a target
 */
router.get('/findings/:target', async (req, res) => {
  const { target } = req.params;
  const { collection, severity } = req.query;

  try {
    const script = `cat /tmp/forensics/findings_*.json 2>/dev/null || echo '{"findings":[]}'`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });

    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      try {
        const parsed = JSON.parse(output);
        let items = parsed.findings || [];
        if (severity) {
          items = items.filter(f => f.severity === severity || severityLevel(f.severity) >= severityLevel(severity));
        }
        findings[minion] = items;
      } catch {
        findings[minion] = parseAnalysisOutput(output);
      }
    }

    res.json({ success: true, findings });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/timeline/:target
 * Get file timeline for a target
 */
router.get('/timeline/:target', async (req, res) => {
  const { target } = req.params;
  const { collection, limit = 200 } = req.query;
  const maxEntries = parseInt(limit) || 200;

  try {
    // Try to read pre-collected tarball data first
    let useLocal = false;
    let timelineText = '', lsattrText = '', auditText = '';

    if (collection) {
      const localPath = getLocalArtifactPath(target, collection);
      if (localPath) {
        try {
          const r1 = await execLocal('tar', ['xzf', localPath, '-O', './files/file_timeline.txt']);
          timelineText = r1.stdout || '';
          useLocal = true;
        } catch {}
        if (useLocal) {
          try {
            const r2 = await execLocal('tar', ['xzf', localPath, '-O', './files/lsattr.txt']);
            lsattrText = r2.stdout || '';
          } catch {}
          try {
            const r3 = await execLocal('tar', ['xzf', localPath, '-O', './files/audit_editors.txt']);
            auditText = r3.stdout || '';
          } catch {}
        }
      }
      if (!useLocal) {
        // Try via Salt
        const esc = collection.replace(/'/g, "\\'");
        try {
          const r = await saltClient.cmd(target, `tar xzf '${esc}' -O './files/file_timeline.txt' 2>/dev/null`, { shell: '/bin/bash', timeout: 60 });
          const out = r[target] || r[Object.keys(r)[0]] || '';
          if (typeof out === 'string' && out.trim()) {
            timelineText = out;
            useLocal = true;
            try {
              const r2 = await saltClient.cmd(target, `tar xzf '${esc}' -O './files/lsattr.txt' 2>/dev/null`, { shell: '/bin/bash', timeout: 30 });
              lsattrText = typeof (r2[target] || r2[Object.keys(r2)[0]]) === 'string' ? (r2[target] || r2[Object.keys(r2)[0]]) : '';
            } catch {}
            try {
              const r3 = await saltClient.cmd(target, `tar xzf '${esc}' -O './files/audit_editors.txt' 2>/dev/null`, { shell: '/bin/bash', timeout: 30 });
              auditText = typeof (r3[target] || r3[Object.keys(r3)[0]]) === 'string' ? (r3[target] || r3[Object.keys(r3)[0]]) : '';
            } catch {}
          }
        } catch {}
      }
    }

    if (useLocal && timelineText.trim()) {
      // Build lsattr map: path -> flags
      const flagsMap = {};
      for (const line of lsattrText.split('\n')) {
        const m = line.match(/^(\S+)\s+(.+)$/);
        if (m) flagsMap[m[2]] = m[1];
      }

      // Build audit editor map: path -> last editor info
      // Format: tab-separated: path\tauid\tcomm
      const editorMap = {};
      for (const line of auditText.split('\n')) {
        if (!line.trim() || line.startsWith('#')) continue;
        const cols = line.split('\t');
        if (cols.length >= 2) {
          const p = cols[0].trim();
          const auid = cols[1] ? cols[1].trim() : '';
          const comm = cols[2] ? cols[2].trim() : '';
          if (p && auid) {
            editorMap[p] = auid + (comm && comm !== 'stat' ? ' via ' + comm : '');
          }
        }
      }

      // Parse file_timeline.txt: epoch\tperms\tsize\tuser\tgroup\tpath
      const entries = [];
      for (const line of timelineText.split('\n')) {
        if (!line.trim() || line.startsWith('#')) continue;
        const cols = line.split('\t');
        if (cols.length < 6) continue;
        const epoch = parseFloat(cols[0]) || 0;
        const p = cols[5];
        if (p && (p.startsWith('/tmp/forensics/') || p.startsWith('/tmp/uac_scan_') || p.startsWith('/opt/uac/') || p.startsWith('/var/cache/salt/') || p.startsWith('/tmp/salt-'))) continue;
        const rawFlags = flagsMap[p] || '';
        // Translate lsattr flags to readable labels
        let flags = '';
        if (rawFlags.includes('i')) flags += 'immutable ';
        if (rawFlags.includes('a')) flags += 'append-only ';
        if (rawFlags.includes('s')) flags += 'secure-delete ';
        flags = flags.trim();

        entries.push({
          path: p,
          time: new Date(epoch * 1000).toISOString(),
          perms: cols[1] || '',
          size: parseInt(cols[2]) || 0,
          owner: (cols[3] || '') + ':' + (cols[4] || ''),
          flags,
          editor: editorMap[p] || ''
        });
      }

      res.json({ success: true, entries: entries.slice(0, maxEntries), source: 'tarball', note: 'Files modified by the forensic scan itself are excluded.' });
    } else {
      // Fallback: live find command
      const script = `find /var/log/ /etc/ -maxdepth 2 -type f -printf '%T@ %m %u %s %p\\n' 2>/dev/null | sort -rn | head -${maxEntries}`;
      const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 60 });

      const entries = [];
      for (const [minion, output] of Object.entries(result)) {
        if (typeof output === 'string') {
          for (const line of output.split('\n').filter(l => l.trim())) {
            const parts = line.split(' ');
            const mtime = parseFloat(parts[0]) || 0;
            const filePath = parts.slice(4).join(' ');
            if (filePath.startsWith('/tmp/forensics/') || filePath.startsWith('/tmp/uac_scan_') || filePath.startsWith('/opt/uac/') || filePath.startsWith('/var/cache/salt/') || filePath.startsWith('/tmp/salt-')) continue;
            entries.push({
              path: filePath,
              time: new Date(mtime * 1000).toISOString(),
              perms: parts[1] || '',
              size: parseInt(parts[3]) || 0,
              owner: (parts[2] || '') + ':',
              flags: '',
              editor: ''
            });
          }
        }
      }

      res.json({ success: true, entries, source: 'live' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/metadata/:target
 * Get collection metadata for a target
 */
router.get('/metadata/:target', async (req, res) => {
  const { target } = req.params;
  const { collection } = req.query;

  try {
    const script = `cat /tmp/forensics/metadata.json 2>/dev/null || echo '{"collected_at":"unknown","hostname":"unknown","level":"unknown"}'`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });

    const metadata = {};
    for (const [minion, output] of Object.entries(result)) {
      try {
        metadata[minion] = JSON.parse(output);
      } catch {
        metadata[minion] = { raw: output };
      }
    }

    res.json({ success: true, metadata });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Helper Functions
// ============================================================

function severityLevel(sev) {
  const levels = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return levels[(sev || '').toLowerCase()] || 0;
}

function buildToolInstallScript() {
  // Read from external script file for maintainability and testability
  const scriptPath = path.join(__dirname, '../../scripts/linux/security/install-forensics-tools.sh');
  try {
    return fs.readFileSync(scriptPath, 'utf8');
  } catch (err) {
    logger.error(`Failed to read install-forensics-tools.sh: ${err.message}`);
    // Fallback to minimal inline script if file not found
    return `#!/bin/bash
set -euo pipefail
echo "[ERROR] install-forensics-tools.sh not found at ${scriptPath}"
echo "[ERROR] Please ensure the script exists in scripts/linux/security/"
exit 1
`;
  }
}

function buildCollectScript(level, opts = {}) {
  const base = `
export FDIR="/tmp/forensics/.collecting_$$"
export OUTDIR="/tmp/forensics"
mkdir -p "$FDIR" "$OUTDIR"
export TS=$(date +%Y%m%d_%H%M%S)
export HOST=$(hostname)

# Cleanup trap: kill child processes on exit/timeout to prevent orphans and OOM
cleanup() {
  pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT TERM INT

echo '{"collected_at":"'$(date -Iseconds)'","hostname":"'$HOST'","level":"__LEVEL__"}' > "$FDIR/metadata.json"
`;

  const quickSteps = `
# Quick: basic triage (flat files, no subdirs)
hostname > "$FDIR/hostname.txt"
date > "$FDIR/date.txt"
uname -a > "$FDIR/uname.txt"
id > "$FDIR/id.txt"
w > "$FDIR/who.txt" 2>/dev/null
ps auxf > "$FDIR/ps.txt" 2>/dev/null
ss -tlnp > "$FDIR/ss_listen.txt" 2>/dev/null
cat /etc/passwd > "$FDIR/passwd.txt" 2>/dev/null
last -20 > "$FDIR/last.txt" 2>/dev/null
echo "Quick collection complete"
`;

  const standardSteps = `
# Standard: organized collection (includes all quick data + more)
for d in system network persistence users processes files logs; do
  mkdir -p "$FDIR/$d"
done

# --- System ---
hostname > "$FDIR/system/hostname.txt"
date > "$FDIR/system/date.txt"
uname -a > "$FDIR/system/uname.txt"
id > "$FDIR/system/id.txt"
w > "$FDIR/system/who.txt" 2>/dev/null
systemctl list-units --type=service > "$FDIR/system/services.txt" 2>/dev/null

# --- Users ---
cat /etc/passwd > "$FDIR/users/passwd.txt" 2>/dev/null
cp /etc/shadow "$FDIR/users/shadow.txt" 2>/dev/null
cp /etc/group "$FDIR/users/group.txt" 2>/dev/null
last -20 > "$FDIR/users/last_logins.txt" 2>/dev/null
crontab -l > "$FDIR/persistence/crontab_root.txt" 2>/dev/null
ls -la /etc/cron.d/ > "$FDIR/persistence/cron_d.txt" 2>/dev/null
cat /etc/crontab > "$FDIR/persistence/etc_crontab.txt" 2>/dev/null

# --- Network ---
ss -tlnp > "$FDIR/network/listening_ports.txt" 2>/dev/null
ss -anp > "$FDIR/network/all_sockets.txt" 2>/dev/null
ip addr > "$FDIR/network/ip_addresses.txt" 2>/dev/null
ip route > "$FDIR/network/routes.txt" 2>/dev/null
iptables -L -n -v > "$FDIR/network/iptables.txt" 2>/dev/null

# --- Processes ---
ps auxf > "$FDIR/processes/ps_full.txt" 2>/dev/null

# --- Files ---
find /tmp /var/tmp -type f -mtime -1 -ls > "$FDIR/files/recent_tmp.txt" 2>/dev/null

# --- File Timeline & Editor Tracking ---
echo "# Files modified in last 7 days" > "$FDIR/files/file_timeline.txt"
timeout 60 bash -c 'find / -xdev -type f -mmin -10080 -printf "%T@\\t%M\\t%s\\t%u\\t%g\\t%p\\n" 2>/dev/null | grep -vE "(/tmp/forensics/|/tmp/uac_|/opt/uac/|/var/lib/rkhunter/|/var/lib/clamav/|/var/lib/aide/|/var/cache/salt/|/tmp/salt-|/var/log/salt/)" | sort -rn | head -2000' >> "$FDIR/files/file_timeline.txt"

if command -v ausearch >/dev/null 2>&1; then
  ausearch -ts today -i -sc open,openat,creat,rename,unlink,chmod,chown 2>/dev/null | awk '/^type=PATH/{p="";for(i=1;i<=NF;i++){if($i~/^name=/){gsub(/name=/,"",$i);gsub(/"/,"",$i);p=$i}}} /^type=SYSCALL/{a="";c="";for(i=1;i<=NF;i++){if($i~/^auid=/){gsub(/auid=/,"",$i);gsub(/"/,"",$i);a=$i}if($i~/^comm=/){gsub(/comm=/,"",$i);gsub(/"/,"",$i);c=$i}};if(p&&a)print p"\t"a"\t"c;p=""}' 2>/dev/null | sort -t'	' -k1,1 -u > "$FDIR/files/audit_editors.txt"
fi
if [ ! -s "$FDIR/files/audit_editors.txt" ]; then
  echo "# stat ownership fallback" > "$FDIR/files/audit_editors.txt"
  find /etc /usr/bin /usr/sbin /home -type f -mmin -10080 -printf "%p\t%u\tstat\n" 2>/dev/null | head -2000 >> "$FDIR/files/audit_editors.txt"
fi

echo "Standard collection complete"
`;

  const advancedSteps = `
# Advanced: deep forensics (includes all standard data + more)
mkdir -p "$FDIR/system" "$FDIR/network" "$FDIR/persistence" "$FDIR/users" "$FDIR/processes" "$FDIR/files" "$FDIR/logs"

# --- Files ---
find / -perm -4000 -type f -ls > "$FDIR/files/suid_files.txt" 2>/dev/null
find / -perm -2000 -type f -ls > "$FDIR/files/sgid_files.txt" 2>/dev/null
find /home -name ".*" -type f -ls > "$FDIR/files/hidden_home.txt" 2>/dev/null
ls -la /dev/shm/ > "$FDIR/files/dev_shm.txt" 2>/dev/null
find /etc -name "*.conf" -newer /etc/hostname -ls > "$FDIR/files/recent_conf.txt" 2>/dev/null

# --- System ---
lsmod > "$FDIR/system/lsmod.txt" 2>/dev/null
cat /proc/modules > "$FDIR/system/proc_modules.txt" 2>/dev/null

# --- Network ---
cat /etc/hosts > "$FDIR/network/hosts_file.txt" 2>/dev/null
cat /etc/resolv.conf > "$FDIR/network/dns_resolv.txt" 2>/dev/null

# --- Users ---
ls -la /root/.ssh/ > "$FDIR/users/root_ssh.txt" 2>/dev/null
cat /root/.bash_history > "$FDIR/users/root_history.txt" 2>/dev/null

# --- Logs ---
cp /var/log/auth.log "$FDIR/logs/auth.log" 2>/dev/null || true
cp /var/log/syslog "$FDIR/logs/syslog.log" 2>/dev/null || true
cp /var/log/secure "$FDIR/logs/secure.log" 2>/dev/null || true

# --- File Timeline & Editor Tracking ---
echo "# Files modified in last 7 days" > "$FDIR/files/file_timeline.txt"
timeout 90 bash -c 'find / -xdev -type f -mmin -10080 -printf "%T@\\t%M\\t%s\\t%u\\t%g\\t%p\\n" 2>/dev/null | grep -vE "(/tmp/forensics/|/tmp/uac_|/opt/uac/|/var/lib/rkhunter/|/var/lib/clamav/|/var/lib/aide/|/var/cache/salt/|/tmp/salt-|/var/log/salt/)" | sort -rn | head -3000' >> "$FDIR/files/file_timeline.txt"
timeout 30 bash -c 'lsattr -R /etc /usr/bin /usr/sbin /home 2>/dev/null' > "$FDIR/files/lsattr.txt"

if command -v ausearch >/dev/null 2>&1; then
  ausearch -ts today -i -sc open,openat,creat,rename,unlink,chmod,chown 2>/dev/null | awk '/^type=PATH/{p="";for(i=1;i<=NF;i++){if($i~/^name=/){gsub(/name=/,"",$i);gsub(/"/,"",$i);p=$i}}} /^type=SYSCALL/{a="";c="";for(i=1;i<=NF;i++){if($i~/^auid=/){gsub(/auid=/,"",$i);gsub(/"/,"",$i);a=$i}if($i~/^comm=/){gsub(/comm=/,"",$i);gsub(/"/,"",$i);c=$i}};if(p&&a)print p"\t"a"\t"c;p=""}' 2>/dev/null | sort -t'	' -k1,1 -u > "$FDIR/files/audit_editors.txt"
fi
if [ ! -s "$FDIR/files/audit_editors.txt" ]; then
  echo "# stat ownership fallback" > "$FDIR/files/audit_editors.txt"
  find /etc /usr/bin /usr/sbin /home -type f -mmin -10080 -printf "%p\t%u\tstat\n" 2>/dev/null | head -2000 >> "$FDIR/files/audit_editors.txt"
fi

echo "Advanced collection complete"
`;

  const comprehensiveSteps = `
# Comprehensive: full forensic collection organized by category
# Uses subdirectories for organization; each section has a timeout to prevent hangs

# Create organized subdirectories
for d in system network persistence users processes files logs scanning memory; do
  mkdir -p "$FDIR/$d"
done

# =============================================
# SYSTEM INFORMATION
# =============================================
timeout 30 bash -c 'sha256sum /usr/bin/ssh /usr/bin/sudo /usr/bin/passwd /usr/sbin/sshd /usr/bin/login /usr/bin/su /usr/bin/crontab /usr/bin/at /usr/bin/wget /usr/bin/curl /usr/bin/nc /usr/bin/ncat /usr/bin/python3 /usr/bin/perl /usr/bin/whoami /usr/bin/id /bin/bash /bin/sh /usr/sbin/cron /usr/sbin/useradd /usr/sbin/usermod 2>/dev/null || true' > "$FDIR/system/file_hashes_sha256.txt"
timeout 120 bash -c 'if command -v debsums >/dev/null 2>&1; then debsums -c 2>/dev/null; elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>/dev/null; fi; true' > "$FDIR/system/package_verify.txt"
timeout 30 bash -c 'if command -v dpkg >/dev/null 2>&1; then dpkg -l; elif command -v rpm >/dev/null 2>&1; then rpm -qa | sort; fi' > "$FDIR/system/installed_packages.txt"
timeout 10 bash -c 'mount; echo ""; echo "=== fstab ==="; cat /etc/fstab 2>/dev/null; echo ""; df -h' > "$FDIR/system/mounts_fstab.txt"
timeout 10 bash -c 'cat /etc/environment 2>/dev/null; echo ""; echo "=== Current env ==="; env | sort' > "$FDIR/system/environment.txt"
timeout 5 bash -c 'echo "Tainted: $(cat /proc/sys/kernel/tainted 2>/dev/null)"; echo ""; dmesg 2>/dev/null | tail -50' > "$FDIR/system/kernel_taint.txt"
timeout 10 bash -c 'lsmod 2>/dev/null' > "$FDIR/system/lsmod.txt"
timeout 10 bash -c 'cat /proc/modules 2>/dev/null' > "$FDIR/system/proc_modules.txt"
timeout 10 bash -c 'getenforce 2>/dev/null; sestatus 2>/dev/null; echo ""; aa-status 2>/dev/null; apparmor_status 2>/dev/null' > "$FDIR/system/mac_status.txt"

# =============================================
# NETWORK
# =============================================
timeout 10 bash -c 'ss -tlnp 2>/dev/null' > "$FDIR/network/listening_ports.txt"
timeout 10 bash -c 'ss -anp 2>/dev/null' > "$FDIR/network/all_sockets.txt"
timeout 10 bash -c 'ss -tnp state established 2>/dev/null' > "$FDIR/network/established_connections.txt"
timeout 10 bash -c 'ip addr 2>/dev/null' > "$FDIR/network/ip_addresses.txt"
timeout 10 bash -c 'ip route show table all 2>/dev/null' > "$FDIR/network/routes.txt"
timeout 10 bash -c 'arp -a 2>/dev/null || ip neigh 2>/dev/null' > "$FDIR/network/arp_cache.txt"
timeout 10 bash -c 'cat /etc/resolv.conf 2>/dev/null' > "$FDIR/network/dns_resolv.txt"
timeout 10 bash -c 'cat /etc/hosts 2>/dev/null' > "$FDIR/network/hosts_file.txt"
timeout 15 bash -c 'iptables-save 2>/dev/null; echo ""; echo "=== nft ==="; nft list ruleset 2>/dev/null; echo ""; echo "=== ufw ==="; ufw status verbose 2>/dev/null' > "$FDIR/network/firewall_rules.txt"
timeout 10 bash -c 'ip netns list 2>/dev/null || echo "(none)"' > "$FDIR/network/namespaces.txt"
timeout 15 bash -c '
echo "=== Packet sockets (AF_PACKET) ==="
cat /proc/net/packet 2>/dev/null || echo "(not available)"
echo ""
echo "=== Raw sockets ==="
cat /proc/net/raw 2>/dev/null || echo "(not available)"
cat /proc/net/raw6 2>/dev/null
echo ""
echo "=== ss raw/packet ==="
ss -0 2>/dev/null
ss -w 2>/dev/null
echo ""
echo "=== BPF programs ==="
bpftool prog list 2>/dev/null || echo "(bpftool not available)"
echo ""
echo "=== BPF maps ==="
bpftool map list 2>/dev/null || echo "(bpftool not available)"
echo ""
echo "=== Processes with raw/packet sockets ==="
for pid in /proc/[0-9]*/fd; do
  p=$(dirname "$pid")
  ls -la "$pid" 2>/dev/null | grep -q "socket:" && {
    cat "$p/net/packet" 2>/dev/null | grep -v "^sk" | while read line; do
      echo "PID=$(basename $p) CMD=$(cat $p/cmdline 2>/dev/null | tr "\\0" " ") PACKET_SOCKET: $line"
    done
  }
done 2>/dev/null | head -50
echo ""
echo "=== Socket filters (SO_ATTACH_FILTER) ==="
find /proc/[0-9]*/fdinfo -type f 2>/dev/null | while read fi; do
  if grep -q "sock_filter" "$fi" 2>/dev/null; then
    pid=$(echo "$fi" | cut -d/ -f3)
    echo "PID=$pid CMD=$(cat /proc/$pid/cmdline 2>/dev/null | tr "\\0" " ") HAS_BPF_FILTER"
  fi
done | head -20
echo ""
echo "=== Processes with CAP_NET_RAW ==="
for pid in /proc/[0-9]*/status; do
  if grep -q "CapEff.*0000002" "$pid" 2>/dev/null; then
    p=$(dirname "$pid")
    echo "PID=$(basename $p) CMD=$(cat $p/cmdline 2>/dev/null | tr "\\0" " ") CAP_NET_RAW"
  fi
done 2>/dev/null | head -20
' > "$FDIR/network/bpf_raw_sockets.txt"

# =============================================
# PERSISTENCE MECHANISMS
# =============================================
timeout 10 bash -c 'crontab -l 2>/dev/null; echo ""; for user in $(cut -d: -f1 /etc/passwd); do C=$(crontab -u "$user" -l 2>/dev/null); [ -n "$C" ] && echo "=== $user ===" && echo "$C"; done' > "$FDIR/persistence/crontabs_all_users.txt"
timeout 10 bash -c 'ls -la /etc/cron.d/ 2>/dev/null; echo ""; for f in /etc/cron.d/*; do echo "=== $f ==="; cat "$f" 2>/dev/null; done' > "$FDIR/persistence/cron_d.txt"
timeout 10 bash -c 'cat /etc/crontab 2>/dev/null' > "$FDIR/persistence/etc_crontab.txt"
timeout 10 bash -c 'atq 2>/dev/null || echo "(at not available)"; echo ""; ls -la /var/spool/at/ 2>/dev/null; for f in /var/spool/at/[a-z]*; do echo "=== $f ==="; cat "$f" 2>/dev/null; done' > "$FDIR/persistence/at_jobs.txt"
timeout 15 bash -c 'find /etc/systemd/system/ -name "*.service" -ls 2>/dev/null; echo ""; for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service; do [ -f "$f" ] && echo "=== $f ===" && cat "$f" 2>/dev/null; done' > "$FDIR/persistence/systemd_services.txt"
timeout 10 bash -c 'systemctl list-timers --all --no-pager 2>/dev/null; echo ""; find /etc/systemd/system /usr/lib/systemd/system -name "*.timer" -ls 2>/dev/null' > "$FDIR/persistence/systemd_timers.txt"
timeout 10 bash -c 'ls -la /etc/init.d/ 2>/dev/null; echo ""; for f in /etc/init.d/*; do echo "=== $f ==="; head -15 "$f" 2>/dev/null; echo ""; done' > "$FDIR/persistence/initd_scripts.txt"
timeout 10 bash -c 'cat /etc/rc.local 2>/dev/null || echo "(not found)"; echo ""; echo "=== /etc/rc.d/rc.local ==="; cat /etc/rc.d/rc.local 2>/dev/null || echo "(not found)"' > "$FDIR/persistence/rc_local.txt"
timeout 15 bash -c 'ls -la /etc/profile.d/ 2>/dev/null; echo ""; for f in /etc/profile.d/*.sh; do echo "=== $f ==="; cat "$f" 2>/dev/null; done' > "$FDIR/persistence/profile_d.txt"
timeout 15 bash -c 'cat /etc/bash.bashrc 2>/dev/null; echo ""; echo "=== /etc/profile ==="; cat /etc/profile 2>/dev/null' > "$FDIR/persistence/global_bashrc_profile.txt"
timeout 30 bash -c 'while IFS=: read -r user _ _ _ _ home _; do for rc in .bashrc .profile .bash_profile .bash_login .bash_logout; do [ -f "$home/$rc" ] && echo "=== $user: $home/$rc ===" && cat "$home/$rc" 2>/dev/null; done; done < /etc/passwd' > "$FDIR/persistence/user_rc_files.txt"
timeout 10 bash -c 'cat /etc/ld.so.preload 2>/dev/null || echo "(not found)"; echo ""; ls -la /etc/ld.so.conf.d/ 2>/dev/null; for f in /etc/ld.so.conf.d/*; do echo "=== $f ==="; cat "$f" 2>/dev/null; done; echo ""; grep -r LD_PRELOAD /etc/environment /etc/profile /etc/profile.d/ 2>/dev/null || echo "(no LD_PRELOAD references)"' > "$FDIR/persistence/ld_preload.txt"
timeout 10 bash -c 'ls -la /etc/pam.d/ 2>/dev/null; echo ""; echo "=== Suspicious PAM modules ==="; grep -rE "(pam_exec|pam_script)" /etc/pam.d/ 2>/dev/null || echo "(none)"; echo ""; echo "=== pam_permit usage (verify these are expected) ==="; grep -rn "pam_permit" /etc/pam.d/ 2>/dev/null | grep -v "^#" | grep -v "other:" || echo "(none outside /etc/pam.d/other)"' > "$FDIR/persistence/pam_config.txt"
timeout 10 bash -c 'cat /etc/modules 2>/dev/null; echo ""; ls /etc/modules-load.d/ 2>/dev/null' > "$FDIR/persistence/kernel_modules_autoload.txt"
timeout 15 bash -c 'echo "=== Systemd generators ==="; ls -la /etc/systemd/system-generators/ /usr/local/lib/systemd/system-generators/ /run/systemd/system-generators/ 2>/dev/null || echo "(none)"; echo ""; echo "=== Systemd drop-ins ==="; find /etc/systemd/system /run/systemd/system -name "*.conf" -path "*.d/*" -ls 2>/dev/null; echo ""; echo "=== User services ==="; find /home -path "*/.config/systemd/user/*.service" -ls 2>/dev/null' > "$FDIR/persistence/systemd_generators_dropins.txt"
timeout 10 bash -c 'echo "=== Motd scripts ==="; ls -la /etc/update-motd.d/ 2>/dev/null; echo ""; echo "=== Bash completion ==="; ls -la /etc/bash_completion.d/ 2>/dev/null | head -30; echo ""; echo "=== XDG autostart ==="; find /etc/xdg/autostart /home -name "*.desktop" -path "*autostart*" -ls 2>/dev/null' > "$FDIR/persistence/other_persistence.txt"

# =============================================
# USERS & AUTHENTICATION
# =============================================
timeout 10 bash -c 'cat /etc/passwd 2>/dev/null' > "$FDIR/users/passwd.txt"
timeout 10 bash -c 'cat /etc/shadow 2>/dev/null' > "$FDIR/users/shadow.txt"
timeout 10 bash -c 'cat /etc/group 2>/dev/null' > "$FDIR/users/group.txt"
timeout 10 bash -c 'awk -F: "\\$3==0{print \\$1}" /etc/passwd 2>/dev/null' > "$FDIR/users/uid0_users.txt"
timeout 10 bash -c 'awk -F: "\\$7 !~ /(nologin|false)/ {print \\$1,\\$7}" /etc/passwd 2>/dev/null' > "$FDIR/users/users_with_shells.txt"
timeout 10 bash -c 'cat /etc/sudoers 2>/dev/null; echo ""; ls -la /etc/sudoers.d/ 2>/dev/null; for f in /etc/sudoers.d/*; do echo "=== $f ==="; cat "$f" 2>/dev/null; done' > "$FDIR/users/sudoers.txt"
timeout 10 bash -c 'last -20 2>/dev/null' > "$FDIR/users/last_logins.txt"
timeout 15 bash -c 'lastb 2>/dev/null | head -100' > "$FDIR/users/failed_logins.txt"
timeout 30 bash -c 'cat /etc/ssh/sshd_config 2>/dev/null; echo ""; cat /etc/ssh/sshd_config.d/* 2>/dev/null; echo ""; echo "=== authorized_keys ==="; while IFS=: read -r user _ _ _ _ home _; do [ -f "$home/.ssh/authorized_keys" ] && echo "--- $user ---" && cat "$home/.ssh/authorized_keys" 2>/dev/null; ls "$home/.ssh/id_*" 2>/dev/null | while read k; do echo "Private key: $k"; done; done < /etc/passwd' > "$FDIR/users/ssh_keys_and_config.txt"
timeout 30 bash -c 'while IFS=: read -r user _ _ _ _ home _; do for hist in .bash_history .zsh_history .sh_history; do [ -f "$home/$hist" ] && echo "=== $user: $hist ===" && tail -100 "$home/$hist" 2>/dev/null; done; done < /etc/passwd' > "$FDIR/users/shell_histories.txt"

# =============================================
# PROCESSES
# =============================================
timeout 10 bash -c 'ps auxf 2>/dev/null || ps aux 2>/dev/null' > "$FDIR/processes/ps_full.txt"
timeout 10 bash -c 'ps aux --sort=-%cpu 2>/dev/null | head -25' > "$FDIR/processes/top_cpu.txt"
timeout 10 bash -c 'ps aux --sort=-%mem 2>/dev/null | head -25' > "$FDIR/processes/top_memory.txt"
timeout 10 bash -c 'ps aux | grep -iE "(nc |ncat |nmap |socat |/tmp/|/dev/shm/|reverse|bind.sh|shell|xmrig|minerd|stratum|cryptonight|chisel|ligolo|sliver|cobalt|meterpreter|pspy|linpeas|linenum|wget .*/\\.|curl .*/\\.|python.*-c.*import|perl.*-e.*socket|ruby.*-e.*socket|php.*-r.*exec)" | grep -v grep | grep -v forensics_script | grep -v rammon.sh | grep -v "salt-minion"' > "$FDIR/processes/suspicious_processes.txt"
timeout 60 bash -c 'ps -eo pid --sort=-%cpu --no-headers | head -50 | while read pid; do echo "=== PID $pid ==="; echo "exe: $(readlink /proc/$pid/exe 2>/dev/null)"; echo "cmdline: $(tr "\\0" " " < /proc/$pid/cmdline 2>/dev/null)"; echo "cwd: $(readlink /proc/$pid/cwd 2>/dev/null)"; echo "env_suspicious: $(tr "\\0" "\\n" < /proc/$pid/environ 2>/dev/null | grep -iE "(LD_PRELOAD|LD_LIBRARY_PATH|http_proxy|socks)" || true)"; echo ""; done' > "$FDIR/processes/proc_detail.txt"
timeout 30 bash -c 'find /proc -maxdepth 2 -name exe -exec readlink {} \\; 2>/dev/null | grep "(deleted)"' > "$FDIR/processes/deleted_binaries.txt"
timeout 30 bash -c 'lsof -nP 2>/dev/null | head -500' > "$FDIR/processes/lsof_full.txt"
timeout 60 bash -c 'for pid in $(ls /proc/ 2>/dev/null | grep -E "^[0-9]+$" | head -100); do maps=$(cat /proc/$pid/maps 2>/dev/null | grep -vE "(libc|libm|libdl|libpthread|librt|ld-linux|libgcc|libstdc|vdso|vvar|vsyscall|libselinux|libnss|libresolv)" | grep -E "(/tmp/|/dev/shm/|/var/tmp/|\\(deleted\\))" 2>/dev/null); [ -n "$maps" ] && echo "=== PID $pid ($(readlink /proc/$pid/exe 2>/dev/null)) ===" && echo "$maps"; done' > "$FDIR/processes/suspicious_maps.txt"

# =============================================
# FILES & FILESYSTEM
# =============================================
timeout 30 bash -c 'find / -xdev -perm -4000 -type f -ls 2>/dev/null' > "$FDIR/files/suid_files.txt"
timeout 30 bash -c 'find / -xdev -perm -2000 -type f -ls 2>/dev/null' > "$FDIR/files/sgid_files.txt"
timeout 30 bash -c 'find /etc /usr /var -type f -perm -o+w -ls 2>/dev/null | head -100' > "$FDIR/files/world_writable.txt"
timeout 60 bash -c 'find /etc /usr/bin /usr/sbin /bin /sbin /var/spool /tmp -type f -mmin -60 -ls 2>/dev/null | head -200' > "$FDIR/files/recently_modified.txt"
timeout 30 bash -c 'find /home -name ".*" -type f -ls 2>/dev/null | head -100' > "$FDIR/files/hidden_home.txt"
timeout 15 bash -c 'find /dev/shm -ls 2>/dev/null' > "$FDIR/files/dev_shm.txt"
timeout 15 bash -c 'find /tmp -ls 2>/dev/null | head -300' > "$FDIR/files/tmp_listing.txt"
timeout 30 bash -c 'find /tmp /var/tmp /dev/shm /run -type s -o -type p 2>/dev/null | head -100' > "$FDIR/files/sockets_pipes.txt"
timeout 30 bash -c 'getcap -r /usr /bin /sbin /opt 2>/dev/null' > "$FDIR/files/capabilities.txt"
timeout 15 bash -c '[ -f /.dockerenv ] && echo "FOUND: /.dockerenv"; grep -q docker /proc/1/cgroup 2>/dev/null && echo "FOUND: docker cgroup"; grep -q lxc /proc/1/cgroup 2>/dev/null && echo "FOUND: lxc cgroup"; cat /proc/1/cgroup 2>/dev/null; echo ""; cat /proc/1/status 2>/dev/null | grep -i cap' > "$FDIR/files/container_indicators.txt"
timeout 10 bash -c 'docker ps -a 2>/dev/null; echo ""; docker images 2>/dev/null; echo ""; podman ps -a 2>/dev/null; podman images 2>/dev/null' > "$FDIR/files/docker_podman.txt"
timeout 60 bash -c 'find /var/www /srv/www /opt -type f \\( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \\) -exec grep -lE "(eval|exec|system|passthru|shell_exec|popen|proc_open|base64_decode|assert)" {} \\; 2>/dev/null' > "$FDIR/files/webshell_scan.txt"
echo "# NOTE: Files modified by the forensic scan itself are excluded from this timeline." > "$FDIR/files/file_timeline.txt"
timeout 120 bash -c 'find / -xdev -type f -mmin -10080 -printf "%T@\\t%M\\t%s\\t%u\\t%g\\t%p\\n" 2>/dev/null | grep -vE "(/tmp/forensics/|/tmp/uac_|/opt/uac/|/var/lib/rkhunter/|/var/lib/clamav/|/var/lib/aide/|/var/cache/salt/|/tmp/salt-|/var/log/salt/)" | sort -rn | head -5000' >> "$FDIR/files/file_timeline.txt"
timeout 30 bash -c 'lsattr -R /etc /usr/bin /usr/sbin /home 2>/dev/null' > "$FDIR/files/lsattr.txt"
# Generate audit_editors.txt with tab-separated: path\tauid\tcomm
# Try ausearch first, fall back to stat ownership
if command -v ausearch >/dev/null 2>&1; then
  ausearch -ts today -i -sc open,openat,creat,rename,unlink,chmod,chown 2>/dev/null | \
    awk '/^type=PATH/{p="";for(i=1;i<=NF;i++){if($i~/^name=/){gsub(/name=/,"",$i);gsub(/"/,"",$i);p=$i}}} /^type=SYSCALL/{a="";c="";for(i=1;i<=NF;i++){if($i~/^auid=/){gsub(/auid=/,"",$i);gsub(/"/,"",$i);a=$i}if($i~/^comm=/){gsub(/comm=/,"",$i);gsub(/"/,"",$i);c=$i}};if(p&&a)print p"\t"a"\t"c;p=""}' \
    2>/dev/null | sort -t'	' -k1,1 -u > "$FDIR/files/audit_editors.txt"
fi
if [ ! -s "$FDIR/files/audit_editors.txt" ]; then
  echo "# auditd data unavailable - using stat ownership as fallback" > "$FDIR/files/audit_editors.txt"
  find /etc /usr/bin /usr/sbin /home -type f -mmin -10080 -printf "%p\t%u\tstat\n" 2>/dev/null | head -2000 >> "$FDIR/files/audit_editors.txt"
fi

# =============================================
# LOGS
# =============================================
${opts.skip_logs ? '# Logs skipped by user option' : `
# Comprehensive /var/log collection - preserves directory structure
mkdir -p "$FDIR/logs/var_log"
timeout 120 bash -c '
SKIP_BINS="lastlog btmp wtmp faillog"
find /var/log -type f 2>/dev/null | while read -r f; do
  fname=$(basename "$f")
  skip=0
  for b in $SKIP_BINS; do [ "$fname" = "$b" ] && skip=1 && break; done
  [ $skip -eq 1 ] && continue
  case "$f" in /var/log/journal/*/*.journal*) continue;; esac
  fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
  [ "$fsize" -gt 52428800 ] && continue
  relpath=$(echo "$f" | sed "s|^/var/log/||")
  reldir=$(dirname "$relpath")
  mkdir -p "'"$FDIR/logs/var_log"'/$reldir"
  cp "$f" "'"$FDIR/logs/var_log"'/$relpath" 2>/dev/null
done
' || true
timeout 10 bash -c 'journalctl --no-pager -n 200 2>/dev/null' > "$FDIR/logs/journal_recent.txt" || true
`}
timeout 15 bash -c 'find /var/log -maxdepth 2 -type f -empty -ls 2>/dev/null; echo ""; echo "=== Log sizes ==="; ls -laS /var/log/*.log /var/log/auth.log /var/log/syslog /var/log/secure 2>/dev/null; echo ""; echo "=== Log timestamps ==="; stat /var/log/auth.log /var/log/syslog /var/log/secure 2>/dev/null' > "$FDIR/logs/log_tampering_check.txt"
timeout 10 bash -c 'auditctl -l 2>/dev/null || echo "(auditd not available)"; echo ""; cat /etc/audit/audit.rules 2>/dev/null; cat /etc/audit/rules.d/*.rules 2>/dev/null' > "$FDIR/logs/auditd_rules.txt"

# =============================================
# SECURITY SCANNING (tool-based, sequential to prevent OOM)
# Each scanner runs one at a time to avoid memory exhaustion
# When skip_scans is set, scanners run separately via /api/forensics/scan
# =============================================
${opts.skip_scans ? `
echo "[SCAN] Collection complete — security scans will start automatically (Phase 2)"
echo "[SCAN] Scans run separately for faster initial results"
` : `
echo "[SCAN] Starting security scanners (sequential)..."

echo "[SCAN] 1-2/7 rkhunter + chkrootkit (concurrent)..."
timeout 120 bash -c 'if command -v rkhunter >/dev/null 2>&1; then
  echo "=== Updating rkhunter properties database ==="
  rkhunter --propupd 2>/dev/null || echo "(propupd failed)"
  rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null
else echo "rkhunter not installed - use Auto-Install Tools to install"; fi' > "$FDIR/scanning/rkhunter_results.txt" 2>&1 &
RKH_PID=$!
timeout 90 bash -c 'if command -v chkrootkit >/dev/null 2>&1; then chkrootkit 2>/dev/null; else echo "chkrootkit not installed - use Auto-Install Tools to install"; fi' > "$FDIR/scanning/chkrootkit_results.txt" 2>&1 &
CHK_PID=$!
wait $RKH_PID $CHK_PID
echo "[SCAN] 1-2/7 rkhunter + chkrootkit done"

echo "[SCAN] 3/7 ClamAV..."
timeout 180 bash -c 'if command -v clamscan >/dev/null 2>&1; then
  AVAIL_MB=$(awk "/MemAvailable/{print int(\\$2/1024)}" /proc/meminfo)
  if [ "$AVAIL_MB" -lt 800 ]; then
    echo "Skipping ClamAV (only $AVAIL_MB MB available, need 800MB to avoid OOM)"
  else
    if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
      echo "=== Virus DB missing, running freshclam ==="
      timeout 60 freshclam --quiet 2>/dev/null || echo "freshclam failed - scanning without updated DB"
    fi
    echo "=== ClamAV scan ($AVAIL_MB MB available) ==="
    SCAN_PATHS=""
    for p in /tmp /dev/shm /var/tmp /var/www /run /usr/local/bin /opt; do
      [ -d "$p" ] && SCAN_PATHS="$SCAN_PATHS $p"
    done
    clamscan --infected --recursive --max-filesize=10M --max-scansize=100M --max-recursion=5 --max-files=1000 $SCAN_PATHS 2>/dev/null
  fi
else echo "clamscan not installed - use Auto-Install Tools to install"; fi' > "$FDIR/scanning/clamav_results.txt" 2>&1
echo "[SCAN] 3/7 ClamAV done"

echo "[SCAN] 4/7 AIDE..."
timeout 90 bash -c 'if command -v aide >/dev/null 2>&1; then
  AIDE_CONF=""
  [ -f /etc/aide/aide.conf ] && AIDE_CONF="--config /etc/aide/aide.conf"
  if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
    echo "=== AIDE database not found, initializing ==="
    aide --init $AIDE_CONF 2>&1 | tail -5
    if [ -f /var/lib/aide/aide.db.new ]; then
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      echo "=== Database initialized, running first check ==="
      aide --check $AIDE_CONF 2>/dev/null || true
    elif [ -f /var/lib/aide/aide.db.new.gz ]; then
      mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
      echo "=== Database initialized, running first check ==="
      aide --check $AIDE_CONF 2>/dev/null || true
    else
      echo "AIDE init failed (check /etc/aide/aide.conf or /etc/aide.conf)"
    fi
  else
    aide --check $AIDE_CONF 2>/dev/null || true
  fi
else echo "aide not installed - use Auto-Install Tools to install"; fi' > "$FDIR/scanning/aide_results.txt" 2>&1
echo "[SCAN] 4/7 AIDE done"

echo "[SCAN] 5/7 debsums..."
timeout 90 bash -c 'if command -v debsums >/dev/null 2>&1; then
  echo "=== Changed files (debsums -c) ==="
  debsums -c 2>/dev/null || echo "(no changed files)"
  echo ""
  echo "=== Missing files (debsums -l) ==="
  debsums -l 2>/dev/null | head -50
else echo "debsums not installed (Debian/Ubuntu only)"; fi' > "$FDIR/scanning/debsums_results.txt" 2>&1
echo "[SCAN] 5/7 debsums done"

echo "[SCAN] 6/7 YARA..."
timeout 60 bash -c 'if command -v yara >/dev/null 2>&1; then
  echo "YARA version: $(yara --version 2>/dev/null)"
  RULES=""
  for rdir in /opt/yara-rules /etc/yara /usr/share/yara; do
    [ -d "$rdir" ] && RULES="$rdir"
  done
  if [ -n "$RULES" ]; then
    echo "=== Scanning with rules from $RULES ==="
    find "$RULES" -name "*.yar" -o -name "*.yara" 2>/dev/null | while read r; do
      echo "--- Rule: $r ---"
      yara -r "$r" /tmp /dev/shm /var/tmp /var/www /run /usr/local/bin /opt 2>/dev/null || true
    done
  else
    echo "No YARA rules found in /opt/yara-rules, /etc/yara, or /usr/share/yara"
  fi
else echo "yara not installed - use Auto-Install Tools to install"; fi' > "$FDIR/scanning/yara_results.txt" 2>&1
echo "[SCAN] 6/7 YARA done"

echo "[SCAN] 7/7 UAC..."
timeout 600 bash -c 'if [ -d /opt/uac ] && [ -x /opt/uac/uac ]; then
  echo "=== UAC collection ==="
  UAC_OUT="/tmp/uac_output_$$"
  mkdir -p "$UAC_OUT"
  cd /opt/uac && ./uac -p full "$UAC_OUT" 2>&1 | tail -20
  if ls "$UAC_OUT"/uac-*.tar.gz 1>/dev/null 2>&1; then
    UAC_TAR=$(ls "$UAC_OUT"/uac-*.tar.gz | head -1)
    # Extract select high-value files from UAC into our collection
    UAC_EXTRACT="/tmp/uac_extract_$$"
    mkdir -p "$UAC_EXTRACT"
    tar xzf "$UAC_TAR" -C "$UAC_EXTRACT" --strip-components=1 2>/dev/null
    # Copy valuable UAC artifacts into our directory structure
    # Use find since UAC nests files in varying subdirectories
    uac_copy() { local name="$1" dest="$2"; local f; f=$(find "$UAC_EXTRACT" -name "$name" -type f 2>/dev/null | head -1); [ -n "$f" ] && cp "$f" "$dest" 2>/dev/null; }
    uac_copy "hidden_pids_for_ps_command.txt" "$FDIR/processes/"
    uac_copy "running_processes_full_paths.txt" "$FDIR/processes/"
    uac_copy "hash_executables.md5" "$FDIR/system/"
    uac_copy "hash_executables.sha1" "$FDIR/system/"
    uac_copy "world_writable_directories.txt" "$FDIR/files/"
    uac_copy "world_writable_files.txt" "$FDIR/files/"
    uac_copy "bodyfile.txt" "$FDIR/files/"
    uac_copy "loaded_kernel_modules.txt" "$FDIR/system/"
    # Copy suid/sgid with renamed destination
    f=$(find "$UAC_EXTRACT" -name "suid.txt" -type f 2>/dev/null | head -1); [ -n "$f" ] && cp "$f" "$FDIR/files/uac_suid.txt" 2>/dev/null
    f=$(find "$UAC_EXTRACT" -name "sgid.txt" -type f 2>/dev/null | head -1); [ -n "$f" ] && cp "$f" "$FDIR/files/uac_sgid.txt" 2>/dev/null
    # Copy all of /var/log from UAC (more complete than our selective copies)
    UAC_VARLOG=$(find "$UAC_EXTRACT" -type d -path "*/var/log" 2>/dev/null | head -1)
    if [ -n "$UAC_VARLOG" ]; then
      mkdir -p "$FDIR/logs/var_log_full"
      cp -r "$UAC_VARLOG"/* "$FDIR/logs/var_log_full/" 2>/dev/null
      echo "UAC /var/log copied: $(find "$FDIR/logs/var_log_full" -type f | wc -l) files"
    fi
    rm -rf "$UAC_EXTRACT"
    # Archive the UAC tarball
    cp "$UAC_TAR" "$FDIR/scanning/" 2>/dev/null
    echo "UAC tarball archived: $(ls -lh "$UAC_TAR" 2>/dev/null)"
  fi
  echo "UAC artifacts: $(find "$UAC_OUT" -type f 2>/dev/null | wc -l) files collected"
  rm -rf "$UAC_OUT"
else
  echo "UAC not installed."
  echo "Install: git clone https://github.com/tclahr/uac /opt/uac"
fi' > "$FDIR/scanning/uac_results.txt"
echo "[SCAN] 7/7 UAC done"
echo "[SCAN] All scanners complete"
`}

# =============================================
# MEMORY
# =============================================
cat /proc/meminfo > "$FDIR/memory/meminfo.txt" 2>/dev/null || true
cat /proc/slabinfo > "$FDIR/memory/slabinfo.txt" 2>/dev/null || true
cat /proc/vmstat > "$FDIR/memory/vmstat.txt" 2>/dev/null || true
${opts.memory_dump ? `
# AVML - Acquire Volatile Memory for Linux (full physical memory dump)
timeout 600 bash -c 'if command -v avml >/dev/null 2>&1; then
  echo "=== AVML memory acquisition ==="
  avml "$FDIR/memory/memory.lime" 2>&1 && echo "Memory dump saved: $(ls -lh "$FDIR/memory/memory.lime" 2>/dev/null)" || echo "AVML acquisition failed"
elif [ -x /opt/avml/avml ]; then
  echo "=== AVML memory acquisition (from /opt/avml) ==="
  /opt/avml/avml "$FDIR/memory/memory.lime" 2>&1 && echo "Memory dump saved: $(ls -lh "$FDIR/memory/memory.lime" 2>/dev/null)" || echo "AVML acquisition failed"
else
  echo "AVML not installed."
  echo "Install: wget https://github.com/microsoft/avml/releases/latest/download/avml -O /usr/local/bin/avml && chmod +x /usr/local/bin/avml"
  echo ""
  echo "Falling back to /proc info collection"
  cat /proc/buddyinfo > "$FDIR/memory/buddyinfo.txt" 2>/dev/null || true
  cat /proc/pagetypeinfo > "$FDIR/memory/pagetypeinfo.txt" 2>/dev/null || true
fi' > "$FDIR/memory/avml_acquisition.txt"
` : `
cat /proc/buddyinfo > "$FDIR/memory/buddyinfo.txt" 2>/dev/null || true
`}

${opts.memory_dump ? `
# =============================================
# VOLATILITY3 ANALYSIS (only runs when memory dump is enabled)
# =============================================
echo "[ANALYSIS] Running Volatility3 analysis..."
timeout 300 bash -c 'VOL3=""
if command -v vol >/dev/null 2>&1; then VOL3="vol"
elif command -v vol3 >/dev/null 2>&1; then VOL3="vol3"
elif command -v volatility3 >/dev/null 2>&1; then VOL3="volatility3"
elif python3 -c "import volatility3.cli" 2>/dev/null; then VOL3="python3 -m volatility3.cli"
fi

if [ -z "$VOL3" ]; then
  echo "volatility3 not installed"
  echo "To install: pip3 install volatility3"
else
  echo "Volatility 3 available: $VOL3"
  MEMDUMP="$FDIR/memory/memory.lime"
  if [ -f "$MEMDUMP" ]; then
    echo ""
    echo "=== Memory dump found: $(ls -lh "$MEMDUMP") ==="
    echo ""
    echo "--- linux.pslist (process listing) ---"
    $VOL3 -f "$MEMDUMP" linux.pslist 2>&1 || echo "(pslist failed)"
    echo ""
    echo "--- linux.pstree (process tree) ---"
    $VOL3 -f "$MEMDUMP" linux.pstree 2>&1 || echo "(pstree failed)"
    echo ""
    echo "--- linux.bash (bash history from memory) ---"
    $VOL3 -f "$MEMDUMP" linux.bash 2>&1 || echo "(bash failed)"
    echo ""
    echo "--- linux.check_syscall (syscall hooks) ---"
    $VOL3 -f "$MEMDUMP" linux.check_syscall 2>&1 || echo "(check_syscall failed)"
    echo ""
    echo "--- linux.check_modules (hidden kernel modules) ---"
    $VOL3 -f "$MEMDUMP" linux.check_modules 2>&1 || echo "(check_modules failed)"
    echo ""
    echo "--- linux.sockstat (network connections) ---"
    $VOL3 -f "$MEMDUMP" linux.sockstat 2>&1 || echo "(sockstat failed)"
    echo ""
    echo "--- linux.elfs (injected ELFs) ---"
    $VOL3 -f "$MEMDUMP" linux.elfs 2>&1 || echo "(elfs failed)"
  else
    echo "AVML memory dump not found at $MEMDUMP"
  fi
fi' > "$FDIR/scanning/volatility_results.txt" 2>&1
echo "[ANALYSIS] Volatility3 done"

# Remove memory dump after analysis to avoid multi-GB tarballs
if [ -f "$FDIR/memory/memory.lime" ]; then
  echo "[CLEANUP] Removing memory dump ($(ls -lh "$FDIR/memory/memory.lime" | awk '{print $5}')) after analysis"
  rm -f "$FDIR/memory/memory.lime"
fi
` : `
# Memory dump not enabled - skip volatility analysis
echo "[ANALYSIS] Volatility skipped (memory dump not enabled)"
`}

echo "Comprehensive collection complete"
`;

  let script = base.replace('__LEVEL__', level);
  // Comprehensive already collects everything in organized subdirs — skip quick/standard/advanced duplicates
  if (level === 'comprehensive') {
    script += comprehensiveSteps;
  } else {
    script += quickSteps;
    if (level !== 'quick') script += standardSteps;
    if (level === 'advanced') script += advancedSteps;
  }

  // Create tarball from temp dir, then clean up loose files
  script += `
TARBALL="$OUTDIR/forensics_${level}_\${HOST}_\${TS}.tar.gz"
tar czf "$TARBALL" -C "$FDIR" . 2>/dev/null
rm -rf "$FDIR"
echo ""
echo "Collection saved to: $OUTDIR"
echo "[TARBALL] $TARBALL"
echo "FORENSICS_DONE:$OUTDIR"
`;

  return script;
}

/**
 * Build script for security scanning only (Phase 2)
 * Runs slow scanners: rkhunter, chkrootkit, clamav, aide, debsums, yara, uac
 *
 * When tarball_path is provided, extracts it first, adds scan results, then updates it.
 * This creates a single combined artifact with both collection and scan results.
 */
function buildScanScript(opts = {}) {
  const memoryDump = opts.memory_dump || false;

  return `#!/bin/bash
set -o pipefail
export OUTDIR="/tmp/forensics"
export FDIR="/tmp/forensics_work_$$"
export SCAN_DIR="$FDIR/scanning"
export HOST=$(hostname -s 2>/dev/null || echo "unknown")

# Cleanup trap
cleanup() { pkill -P $$ 2>/dev/null || true; }
trap cleanup EXIT TERM INT

echo "[SCAN_PHASE] Starting security scanners..."
echo "[SCAN_PHASE] Timestamp: $(date -Iseconds)"

# Find the most recent collection tarball for this host
TARBALL=$(ls -t "$OUTDIR"/forensics_*_\${HOST}_*.tar.gz 2>/dev/null | head -1)

if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
  echo "[SCAN_PHASE] Found collection tarball: $TARBALL"
  mkdir -p "$FDIR"
  tar xzf "$TARBALL" -C "$FDIR" 2>/dev/null
  echo "[SCAN_PHASE] Extracted $(find "$FDIR" -type f | wc -l) files"
else
  echo "[SCAN_PHASE] No collection tarball found, creating standalone scan"
  mkdir -p "$FDIR"
  TARBALL=""
fi
mkdir -p "$SCAN_DIR"

# =============================================
# 1-2. RKHUNTER + CHKROOTKIT (concurrent)
# =============================================
echo "[SCAN_STATUS] rkhunter:running chkrootkit:running"
timeout 120 bash -c 'if command -v rkhunter >/dev/null 2>&1; then
  rkhunter --propupd 2>/dev/null || true
  rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null
else echo "rkhunter not installed"; fi' > "$SCAN_DIR/rkhunter_results.txt" 2>&1 &
RKH_PID=$!
timeout 90 bash -c 'if command -v chkrootkit >/dev/null 2>&1; then chkrootkit 2>/dev/null; else echo "chkrootkit not installed"; fi' > "$SCAN_DIR/chkrootkit_results.txt" 2>&1 &
CHK_PID=$!
wait $RKH_PID $CHK_PID
echo "[SCAN_STATUS] rkhunter:done chkrootkit:done"
echo "[SCAN_RESULT] rkhunter=$(wc -l < "$SCAN_DIR/rkhunter_results.txt" 2>/dev/null || echo 0) lines"
echo "[SCAN_RESULT] chkrootkit=$(wc -l < "$SCAN_DIR/chkrootkit_results.txt" 2>/dev/null || echo 0) lines"

# =============================================
# 3. CLAMAV
# =============================================
echo "[SCAN_STATUS] clamav:running"
timeout 180 bash -c 'if command -v clamscan >/dev/null 2>&1; then
  AVAIL_MB=$(awk "/MemAvailable/{print int(\\$2/1024)}" /proc/meminfo)
  if [ "$AVAIL_MB" -lt 800 ]; then
    echo "Skipping ClamAV (only $AVAIL_MB MB available, need 800MB)"
  else
    if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
      timeout 60 freshclam --quiet 2>/dev/null || true
    fi
    SCAN_PATHS=""
    for p in /tmp /dev/shm /var/tmp /var/www /run /usr/local/bin /opt; do
      [ -d "$p" ] && SCAN_PATHS="$SCAN_PATHS $p"
    done
    clamscan --infected --recursive --max-filesize=10M --max-scansize=100M --max-recursion=5 --max-files=1000 $SCAN_PATHS 2>/dev/null
  fi
else echo "clamscan not installed"; fi' > "$SCAN_DIR/clamav_results.txt" 2>&1
echo "[SCAN_STATUS] clamav:done"
CLAM_INFECTED=$(grep -c "FOUND$" "$SCAN_DIR/clamav_results.txt" 2>/dev/null || echo 0)
echo "[SCAN_RESULT] clamav=$CLAM_INFECTED infected"

# =============================================
# 4. AIDE
# =============================================
echo "[SCAN_STATUS] aide:running"
timeout 90 bash -c 'if command -v aide >/dev/null 2>&1; then
  AIDE_CONF=""
  [ -f /etc/aide/aide.conf ] && AIDE_CONF="--config /etc/aide/aide.conf"
  if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
    aide --init $AIDE_CONF 2>&1 | tail -5
    [ -f /var/lib/aide/aide.db.new ] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    [ -f /var/lib/aide/aide.db.new.gz ] && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  fi
  aide --check $AIDE_CONF 2>/dev/null || true
else echo "aide not installed"; fi' > "$SCAN_DIR/aide_results.txt" 2>&1
echo "[SCAN_STATUS] aide:done"
AIDE_CHANGES=$(grep -cE "^(changed|added|removed):" "$SCAN_DIR/aide_results.txt" 2>/dev/null || echo 0)
echo "[SCAN_RESULT] aide=$AIDE_CHANGES changes"

# =============================================
# 5. DEBSUMS
# =============================================
echo "[SCAN_STATUS] debsums:running"
timeout 90 bash -c 'if command -v debsums >/dev/null 2>&1; then
  echo "=== Changed files ==="
  debsums -c 2>/dev/null || echo "(none)"
  echo ""
  echo "=== Missing files ==="
  debsums -l 2>/dev/null | head -50
else echo "debsums not installed (Debian/Ubuntu only)"; fi' > "$SCAN_DIR/debsums_results.txt" 2>&1
echo "[SCAN_STATUS] debsums:done"
DEBSUMS_CHANGED=$(grep -v "^===" "$SCAN_DIR/debsums_results.txt" 2>/dev/null | grep -c "." || echo 0)
echo "[SCAN_RESULT] debsums=$DEBSUMS_CHANGED files"

# =============================================
# 6. YARA
# =============================================
echo "[SCAN_STATUS] yara:running"
timeout 120 bash -c 'if command -v yara >/dev/null 2>&1; then
  RULES=""
  [ -f /etc/yara/master_community_rules.yar ] && RULES="/etc/yara/master_community_rules.yar"
  [ -z "$RULES" ] && for rdir in /opt/yara-rules /etc/yara /usr/share/yara; do [ -d "$rdir" ] && RULES="$rdir"; done
  if [ -n "$RULES" ]; then
    echo "Scanning with: $RULES"
    if [ -f "$RULES" ]; then
      # Scan only regular files to avoid flex scanner errors on sockets/pipes
      for scandir in /tmp /dev/shm /var/tmp /var/www /run /usr/local/bin /opt; do
        [ -d "$scandir" ] && find "$scandir" -type f -size -10M 2>/dev/null | head -500 | xargs -r yara -r "$RULES" 2>/dev/null || true
      done
    else
      find "$RULES" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -10 | while read r; do
        find /tmp /dev/shm /var/tmp -type f -size -10M 2>/dev/null | head -500 | xargs -r yara -r "$r" 2>/dev/null || true
      done
    fi
  else
    echo "No YARA rules found"
  fi
else echo "yara not installed"; fi' > "$SCAN_DIR/yara_results.txt" 2>&1
echo "[SCAN_STATUS] yara:done"
YARA_MATCHES=$(grep -cv "^Scanning\\|^$\\|^yara\\|^No YARA" "$SCAN_DIR/yara_results.txt" 2>/dev/null || echo 0)
echo "[SCAN_RESULT] yara=$YARA_MATCHES matches"

# =============================================
# 7. UAC (optional, slower)
# =============================================
echo "[SCAN_STATUS] uac:running"
# Export SCAN_DIR for the subshell and run UAC with proper output capture
export SCAN_DIR
timeout 300 bash -c '
if [ -d /opt/uac ] && [ -x /opt/uac/uac ]; then
  UAC_OUT="/tmp/uac_scan_$$"
  mkdir -p "$UAC_OUT"
  cd /opt/uac
  echo "Running UAC ir_triage profile..."
  ./uac -p ir_triage "$UAC_OUT" 2>&1
  echo ""
  if ls "$UAC_OUT"/uac-*.tar.gz 1>/dev/null 2>&1; then
    UAC_TAR=$(ls -t "$UAC_OUT"/uac-*.tar.gz | head -1)
    if [ -n "$SCAN_DIR" ] && [ -d "$SCAN_DIR" ]; then
      cp "$UAC_TAR" "$SCAN_DIR/" 2>/dev/null && echo "UAC tarball copied to: $SCAN_DIR/$(basename "$UAC_TAR")"
    else
      echo "UAC tarball: $UAC_TAR (SCAN_DIR not set, not copied)"
    fi
    echo "UAC tarball size: $(ls -lh "$UAC_TAR" | awk "{print \$5}")"
  else
    echo "No UAC tarball found in $UAC_OUT"
    ls -la "$UAC_OUT" 2>/dev/null
  fi
  rm -rf "$UAC_OUT"
else
  echo "UAC not installed at /opt/uac/uac"
fi' > "$SCAN_DIR/uac_results.txt" 2>&1
echo "[SCAN_STATUS] uac:done"

${memoryDump ? `
# =============================================
# 8. MEMORY DUMP + VOLATILITY (using AVML)
# =============================================
echo "[SCAN_STATUS] memory:running"
export SCAN_DIR
timeout 600 bash -c '
MEMDUMP="$SCAN_DIR/memory.lime"
echo "Acquiring memory with AVML to: $MEMDUMP"
if command -v avml >/dev/null 2>&1; then
  avml "$MEMDUMP" 2>&1
  if [ -f "$MEMDUMP" ]; then
    echo "Memory dump acquired: $(ls -lh "$MEMDUMP")"
  else
    echo "ERROR: AVML ran but no dump created"
  fi
elif [ -x /opt/avml/avml ]; then
  /opt/avml/avml "$MEMDUMP" 2>&1
  if [ -f "$MEMDUMP" ]; then
    echo "Memory dump acquired: $(ls -lh "$MEMDUMP")"
  fi
else
  echo "ERROR: AVML not installed, cannot acquire memory"
fi' > "$SCAN_DIR/memory_acquisition.txt" 2>&1
echo "[SCAN_STATUS] memory:done"

echo "[SCAN_STATUS] volatility:running"
export SCAN_DIR
timeout 300 bash -c '
MEMDUMP="$SCAN_DIR/memory.lime"
echo "Analyzing memory dump: $MEMDUMP"

# Find Volatility3
VOL3=""
if command -v vol >/dev/null 2>&1; then VOL3="vol"
elif command -v vol3 >/dev/null 2>&1; then VOL3="vol3"
elif [ -x /opt/volatility3-venv/bin/vol ]; then VOL3="/opt/volatility3-venv/bin/vol"
fi

if [ -z "$VOL3" ]; then
  echo "ERROR: Volatility3 not found"
elif [ ! -f "$MEMDUMP" ]; then
  echo "ERROR: Memory dump not found at $MEMDUMP"
else
  echo "Using Volatility3: $VOL3"
  echo ""
  echo "=== linux.pslist ==="
  $VOL3 -f "$MEMDUMP" linux.pslist 2>&1 || echo "(pslist failed)"
  echo ""
  echo "=== linux.bash ==="
  $VOL3 -f "$MEMDUMP" linux.bash 2>&1 || echo "(bash history failed)"
  echo ""
  echo "=== linux.check_syscall ==="
  $VOL3 -f "$MEMDUMP" linux.check_syscall 2>&1 || echo "(syscall check failed)"
  # Remove dump after analysis to save space
  rm -f "$MEMDUMP"
  echo ""
  echo "Memory dump removed after analysis"
fi' > "$SCAN_DIR/volatility_results.txt" 2>&1
echo "[SCAN_STATUS] volatility:done"
` : `
echo "[SCAN_STATUS] memory:skipped volatility:skipped"
`}

# =============================================
# SUMMARY
# =============================================
echo ""
echo "[SCAN_PHASE] All scanners complete"
echo "[SCAN_SUMMARY]"
echo "  rkhunter: $([ -f "$SCAN_DIR/rkhunter_results.txt" ] && echo "done" || echo "failed")"
echo "  chkrootkit: $([ -f "$SCAN_DIR/chkrootkit_results.txt" ] && echo "done" || echo "failed")"
echo "  clamav: $CLAM_INFECTED infected files"
echo "  aide: $AIDE_CHANGES changes detected"
echo "  debsums: $DEBSUMS_CHANGED modified files"
echo "  yara: $YARA_MATCHES matches"
echo "  uac: $([ -f "$SCAN_DIR/uac_results.txt" ] && echo "done" || echo "skipped")"
${memoryDump ? 'echo "  memory: done"' : 'echo "  memory: skipped"'}

# =============================================
# UPDATE TARBALL WITH SCAN RESULTS
# =============================================
if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
  echo ""
  echo "[SCAN_PHASE] Updating tarball with scan results..."
  # Re-create tarball with both collection and scan data
  tar czf "$TARBALL" -C "$FDIR" . 2>/dev/null
  echo "[SCAN_PHASE] Updated: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
  echo "[TARBALL_UPDATED] $TARBALL"
else
  # No original tarball - create new one with just scan results
  HOST=$(hostname -s 2>/dev/null || echo "unknown")
  TS=$(date +%Y%m%d_%H%M%S)
  NEW_TARBALL="$OUTDIR/forensics_scan_\${HOST}_\${TS}.tar.gz"
  mkdir -p "$OUTDIR"
  tar czf "$NEW_TARBALL" -C "$FDIR" . 2>/dev/null
  echo "[SCAN_PHASE] Created: $NEW_TARBALL"
  echo "[TARBALL_CREATED] $NEW_TARBALL"
fi

# Cleanup work directory
rm -rf "$FDIR"

echo ""
echo "SCAN_DONE"
`;
}

function buildAnalysisScript() {
  return `
echo "=== FORENSIC ANALYSIS ==="
echo ""

echo "[CATEGORY:rootkit_indicators]"
echo "[SEVERITY:critical]"
# Check for hidden processes
HIDDEN=$(ps aux | awk '{print $2}' | sort -n | uniq -d)
if [ -n "$HIDDEN" ]; then echo "[FINDING] Duplicate PIDs detected: $HIDDEN"; fi
# Check for rootkit files
for f in /usr/bin/.sshd /tmp/.ice-unix/.x /dev/shm/.x /dev/.udev/rules.d /usr/lib/libamplify.so; do
  [ -e "$f" ] && echo "[FINDING] Suspicious file: $f"
done
# Check /proc for hidden
ls /proc/*/exe 2>/dev/null | while read p; do
  readlink "$p" 2>/dev/null | grep -q '(deleted)' && echo "[FINDING] Deleted binary running: $p ($(cat /proc/$(echo "$p" | cut -d/ -f3)/cmdline 2>/dev/null | tr '\\0' ' ' | head -c 100))"
done
echo ""

echo "[CATEGORY:persistence_mechanisms]"
echo "[SEVERITY:high]"
# Cron - only flag non-standard entries
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | grep -vE "(apt|unattended|logrotate|anacron|certbot|freshclam|aide|fstrim|e2scrub)" | while read line; do echo "[FINDING] Root cron: $line"; done
# Cron.d - only flag non-standard entries
ls /etc/cron.d/ 2>/dev/null | grep -vE "^(e2scrub_all|popularity-contest|sysstat|certbot|0hourly|raid-check|\.placeholder)$" | while read f; do echo "[FINDING] Non-standard cron.d entry: $f"; done
# Systemd - only new services added after OS install
find /etc/systemd/system/ -name "*.service" -newer /etc/hostname -not -name "salt-*" -not -name "clamav-*" -not -name "snap*" 2>/dev/null | while read f; do echo "[FINDING] New systemd service: $f"; done
# Init.d - only flag non-standard
ls /etc/init.d/ 2>/dev/null | grep -vE "^(README|skeleton|cron|ssh|sshd|rsyslog|networking|udev|procps|kmod|hwclock|keyboard-setup|console-setup|screen-cleanup|dbus|apparmor|ufw|salt-minion|salt-master|salt-api|auditd|halt|killall|single|rc|rcS|sendsigs|umountfs|umountnfs|umountroot|reboot|bootclean|checkfs|checkroot|mtab|cryptdisks|hostname|hwclockfirst|mountall|mountdevsubfs|mountkernfs|mountnfs|urandom)$" | while read f; do echo "[FINDING] Non-standard init script: $f"; done
# LD_PRELOAD
[ -s /etc/ld.so.preload ] && echo "[FINDING] ld.so.preload has entries: $(cat /etc/ld.so.preload)"
grep -rE "LD_PRELOAD" /etc/environment /etc/profile /etc/profile.d/ 2>/dev/null | grep -v "^#" | while read line; do echo "[FINDING] LD_PRELOAD reference: $line"; done
# Suspicious PAM
grep -rE "(pam_exec|pam_script)" /etc/pam.d/ 2>/dev/null | grep -v "^#" | while read line; do echo "[FINDING] Suspicious PAM module: $line"; done
echo ""

echo "[CATEGORY:suspicious_users]"
echo "[SEVERITY:high]"
# UID 0 users (other than root)
awk -F: '$3==0{print $1}' /etc/passwd | while read u; do
  [ "$u" != "root" ] && echo "[FINDING] Non-root UID 0 user: $u"
done
# Empty passwords
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read u; do echo "[FINDING] Empty password: $u"; done
# Users with shells - only flag non-standard ones (not root, not known system users)
awk -F: '$7 !~ /(nologin|false|sync)/ && $3 >= 1000 {print $1":"$3":"$7}' /etc/passwd | while read u; do echo "[FINDING] User with login shell (uid>=1000): $u"; done
awk -F: '$7 !~ /(nologin|false|sync)/ && $3 > 0 && $3 < 1000 && $1 !~ /^(root|vagrant|ubuntu|centos|ec2-user|admin|salt|saltadmin)$/ {print $1":"$3":"$7}' /etc/passwd | while read u; do echo "[FINDING] System user with login shell: $u"; done
echo ""

echo "[CATEGORY:network_anomalies]"
echo "[SEVERITY:high]"
# Only flag unexpected listeners (not salt, ssh, systemd-resolve, chronyd, node)
ss -tlnp 2>/dev/null | tail -n+2 | grep -vE '(salt-|sshd|systemd-|chronyd|node |ntpd|dnsmasq|unbound)' | while read line; do echo "[FINDING] Unexpected listener: $line"; done
# Established connections to unusual destinations (not salt master, not DNS, not localhost)
ss -tnp state established 2>/dev/null | tail -n+2 | grep -vE '(:4505|:4506|:53 |127\\.0\\.0\\.|::1|:22 )' | while read line; do echo "[FINDING] Non-salt established connection: $line"; done
# Raw/packet sockets (BPFDoor, sniffers, backdoors)
cat /proc/net/packet 2>/dev/null | tail -n+2 | while read line; do
  INODE=$(echo "$line" | awk '{print $9}')
  for pid in /proc/[0-9]*/fd/*; do
    if readlink "$pid" 2>/dev/null | grep -q "socket:\\[$INODE\\]"; then
      P=$(echo "$pid" | cut -d/ -f3)
      CMD=$(cat /proc/$P/cmdline 2>/dev/null | tr '\\0' ' ' | head -c 100)
      echo "[FINDING] Packet socket (AF_PACKET): PID=$P CMD=$CMD"
    fi
  done 2>/dev/null
done
cat /proc/net/raw 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Raw socket: $line"; done
# BPF programs (eBPF backdoors)
bpftool prog list 2>/dev/null | grep -vE "^$" | while read line; do echo "[FINDING] BPF program loaded: $line"; done
echo ""

echo "[CATEGORY:suspicious_processes]"
echo "[SEVERITY:medium]"
# Only flag actually suspicious processes, not top CPU consumers
ps aux | grep -iE '(nc -l|ncat -l|ncat -e|nc -e|nmap |socat |/tmp/[^ ]*$|/dev/shm/|reverse|bind.sh|xmrig|minerd|stratum|cryptonight|chisel|ligolo|sliver|cobalt|meterpreter|pspy|linpeas|linenum)' | grep -v grep | while read line; do echo "[FINDING] Suspicious process: $line"; done
# Processes running from /tmp or /dev/shm
ls -la /proc/*/exe 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' | while read line; do echo "[FINDING] Process running from temp dir: $line"; done
echo ""

echo "[CATEGORY:suid_binaries]"
echo "[SEVERITY:medium]"
# Only flag non-standard SUID binaries
KNOWN_SUID="mount|umount|su|sudo|passwd|chsh|chfn|newgrp|gpasswd|ping|ping6|traceroute|fusermount|fusermount3|pkexec|crontab|at|ssh-keysign|Xorg|unix_chkpwd|pam_timestamp_check|staprun|userhelper|mount.nfs|mount.cifs|polkit-agent-helper-1|snap-confine|chromium-sandbox|chage|expiry|wall|write|locate|dotlockfile|bwrap|dbus-daemon-launch-helper|ntfs-3g"
find / -xdev -perm -4000 -type f 2>/dev/null | while read f; do
  BN=$(basename "$f")
  echo "$BN" | grep -qE "^($KNOWN_SUID)$" || echo "[FINDING] Non-standard SUID binary: $f"
done
echo ""

echo "[CATEGORY:ssh_config]"
echo "[SEVERITY:medium]"
cat /root/.ssh/authorized_keys 2>/dev/null | grep -v "^#" | grep -v "^$" | while read key; do echo "[FINDING] Root SSH authorized key: $(echo $key | awk '{print $NF}')"; done
find /home -name authorized_keys -type f 2>/dev/null | while read f; do
  COUNT=$(grep -c -v "^#" "$f" 2>/dev/null | grep -v "^0$")
  [ -n "$COUNT" ] && echo "[FINDING] SSH authorized_keys: $f ($COUNT keys)"
done
echo ""

echo "[CATEGORY:file_integrity]"
echo "[SEVERITY:medium]"
find /usr/bin /usr/sbin /bin /sbin -newer /etc/hostname -type f 2>/dev/null | head -20 | while read f; do echo "[FINDING] Modified binary: $f"; done
echo ""

echo "[CATEGORY:kernel_modules]"
echo "[SEVERITY:medium]"
# Only flag suspicious/uncommon kernel modules, not all loaded modules
lsmod 2>/dev/null | tail -n+2 | awk '{print $1}' | grep -vE "^(ext4|xfs|btrfs|vfat|fat|nfs|nfsd|overlay|bridge|br_netfilter|ip_tables|ip6_tables|iptable_|ip6table_|nf_|xt_|x_tables|ebtable|ebtables|dm_|sd_|sr_mod|cdrom|ahci|libahci|libata|scsi_|virtio|vmw_|hv_|hyperv|xen_|kvm|irqbypass|drm|i2c_|snd_|soundcore|pcspkr|joydev|input_|hid_|usbhid|ehci|xhci|ohci|uhci|usb_|usbcore|mousedev|evdev|psmouse|serio_raw|atkbd|i8042|rtc_|ptp|pps_|acpi_|button|battery|ac|thermal|processor|fan|intel_|amd_|e1000|igb|ixgb|i40e|bnx|tg3|r8169|sky2|tulip|8139|forcedeth|vmxnet|ena|bonding|veth|macvlan|ipvlan|8021q|garp|mrp|stp|llc|sunrpc|auth_rpcgss|nfsv|lockd|grace|fscache|cachefiles|isofs|udf|squashfs|loop|nbd|fuse|cuse|configfs|efivarfs|autofs|pstore|ramoops|reed_solomon|crc|ghash|aes|sha|md5|crypto_|algif_|af_alg|rng_|drbg|ansi_cprng|lz4|zstd|zlib|deflate|lzo|binfmt_misc|coretemp|edac_|nfit|libnvdimm|nd_|dax|tcp_|udp_|ipv6|unix|af_packet|netlink|rfkill|cfg80211|mac80211|bluetooth|bnep|rfcomm|cls_|sch_|net_cls|net_prio|vhost|vsock|vmci|ppdev|parport|lp|sg|bsg|ses|enclosure|gpio|pinctrl|regulator|watchdog|mei|tpm|rndis|cdc_|raw|iosf_mbi|wmi|video|backlight|dell_|hp_|thinkpad_|ideapad_|asus_|apple_|applesmc|msr|cpuid|fjes|nls_|mac_hid|mptbase|mptsas|mptscsih|mptspi|mptctl|vmw_balloon|vmw_vmci|vmw_vsock|vmwgfx|hv_balloon|hv_utils|hv_kvp|hv_vss|hv_fcopy|hv_netvsc|hv_storvsc|pci_hyperv)" | while read mod; do echo "[FINDING] Uncommon kernel module: $mod"; done
echo ""

echo "[CATEGORY:scheduled_tasks]"
echo "[SEVERITY:medium]"
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$" | grep -vE "(apt|unattended|logrotate|anacron|certbot|freshclam|aide|fstrim|e2scrub)" | while read line; do echo "[FINDING] Cron ($user): $line"; done
done
echo ""

echo "[CATEGORY:log_analysis]"
echo "[SEVERITY:low]"
grep -i "failed\\|error\\|denied" /var/log/auth.log 2>/dev/null | tail -10 | while read line; do echo "[FINDING] Auth log: $line"; done
echo ""

echo "[CATEGORY:environment]"
echo "[SEVERITY:info]"
echo "[FINDING] Hostname: $(hostname)"
echo "[FINDING] Kernel: $(uname -r)"
echo "[FINDING] Uptime: $(uptime)"
echo "[FINDING] Date: $(date -Iseconds)"
echo ""

echo "[CATEGORY:docker_containers]"
echo "[SEVERITY:info]"
docker ps -a --format '{{.Names}} {{.Status}} {{.Image}}' 2>/dev/null | while read line; do echo "[FINDING] Container: $line"; done
echo ""

echo "=== ANALYSIS COMPLETE ==="
`;
}

function buildTargetedAnalysisScript(types, tarball) {
  const sections = [];
  if (types.includes('rootkit')) {
    sections.push(`echo "[CATEGORY:rootkit_indicators]"; echo "[SEVERITY:critical]"; for f in /usr/bin/.sshd /tmp/.ice-unix/.x /dev/shm/.x /dev/.udev/rules.d; do [ -e "$f" ] && echo "[FINDING] Suspicious file: $f"; done; ls /proc/*/exe 2>/dev/null | while read p; do readlink "$p" 2>/dev/null | grep -q '(deleted)' && echo "[FINDING] Deleted binary: $p"; done`);
  }
  if (types.includes('persistence')) {
    sections.push(`echo "[CATEGORY:persistence_mechanisms]"; echo "[SEVERITY:high]"; crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | grep -vE "(apt|unattended|logrotate|anacron|certbot|freshclam|aide)" | while read line; do echo "[FINDING] Root cron: $line"; done; find /etc/systemd/system/ -name "*.service" -newer /etc/hostname -not -name "salt-*" -not -name "clamav-*" 2>/dev/null | while read f; do echo "[FINDING] New service: $f"; done; [ -s /etc/ld.so.preload ] && echo "[FINDING] ld.so.preload has entries"; grep -rE "(pam_exec|pam_script)" /etc/pam.d/ 2>/dev/null | grep -v "^#" | while read line; do echo "[FINDING] Suspicious PAM: $line"; done`);
  }
  if (types.includes('network')) {
    sections.push(`echo "[CATEGORY:network_anomalies]"; echo "[SEVERITY:high]"; ss -tlnp 2>/dev/null | tail -n+2 | grep -vE '(salt-|sshd|systemd-|chronyd|node |ntpd)' | while read line; do echo "[FINDING] Unexpected listener: $line"; done; ss -tnp state established 2>/dev/null | tail -n+2 | grep -vE '(:4505|:4506|:53 |127\\.0\\.0\\.|::1|:22 )' | while read line; do echo "[FINDING] Non-salt connection: $line"; done`);
  }
  if (types.includes('users')) {
    sections.push(`echo "[CATEGORY:suspicious_users]"; echo "[SEVERITY:high]"; awk -F: '$3==0{print $1}' /etc/passwd | while read u; do [ "$u" != "root" ] && echo "[FINDING] UID 0: $u"; done; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read u; do echo "[FINDING] Empty password: $u"; done; awk -F: '$7 !~ /(nologin|false|sync)/ && $3 >= 1000 {print $1":"$3":"$7}' /etc/passwd | while read u; do echo "[FINDING] User with shell: $u"; done`);
  }
  if (types.includes('processes')) {
    sections.push(`echo "[CATEGORY:suspicious_processes]"; echo "[SEVERITY:medium]"; ps aux | grep -iE '(nc -[le]|ncat -[le]|nmap |socat |/dev/shm/|xmrig|minerd|chisel|ligolo|sliver|cobalt|meterpreter|pspy|linpeas)' | grep -v grep | while read line; do echo "[FINDING] Suspicious: $line"; done; ls -la /proc/*/exe 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' | while read line; do echo "[FINDING] Temp dir process: $line"; done`);
  }
  return sections.join('\necho ""\n');
}

function parseAnalysisOutput(output) {
  if (typeof output !== 'string') return [];
  const findings = [];
  let currentCategory = 'unknown';
  let currentSeverity = 'info';

  for (const line of output.split('\n')) {
    const catMatch = line.match(/\[CATEGORY:(\w+)\]/);
    if (catMatch) { currentCategory = catMatch[1]; continue; }

    const sevMatch = line.match(/\[SEVERITY:(\w+)\]/);
    if (sevMatch) { currentSeverity = sevMatch[1]; continue; }

    const findMatch = line.match(/\[FINDING\]\s*(.*)/);
    if (findMatch) {
      findings.push({
        category: currentCategory,
        severity: currentSeverity,
        message: findMatch[1],
        timestamp: new Date().toISOString()
      });
    }
  }
  return findings;
}

module.exports = router;
