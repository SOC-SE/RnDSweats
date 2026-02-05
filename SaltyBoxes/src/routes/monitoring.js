/**
 * Monitoring Routes
 *
 * Scheduled checks with change detection. Captures baselines of
 * system state, then compares subsequent checks to detect drift.
 *
 * @module routes/monitoring
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { client: saltClient } = require('../lib/salt-client');
const scheduler = require('../lib/scheduler');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

router.use(requireAuth);

// Persistence paths
const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const BASELINES_FILE = path.join(DATA_DIR, 'baselines.json');
const CHANGES_FILE = path.join(DATA_DIR, 'changes.json');

// In-memory stores loaded from disk
let baselines = {};
let changes = [];

// Load persisted data
function loadData() {
  try {
    if (fs.existsSync(BASELINES_FILE)) {
      baselines = JSON.parse(fs.readFileSync(BASELINES_FILE, 'utf8'));
    }
  } catch (e) { baselines = {}; }
  try {
    if (fs.existsSync(CHANGES_FILE)) {
      changes = JSON.parse(fs.readFileSync(CHANGES_FILE, 'utf8'));
    }
  } catch (e) { changes = []; }
}

function saveBaselines() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BASELINES_FILE, JSON.stringify(baselines, null, 2));
  } catch (e) { logger.error('Failed to save baselines', e); }
}

function saveChanges() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    // Keep rolling 1000 changes
    if (changes.length > 1000) changes = changes.slice(-1000);
    fs.writeFileSync(CHANGES_FILE, JSON.stringify(changes, null, 2));
  } catch (e) { logger.error('Failed to save changes', e); }
}

loadData();

// ============================================================
// Data Collection Functions
// ============================================================

const CHECK_TYPES = ['users', 'services', 'network', 'cron', 'processes'];

async function collectCheck(targets, checkType) {
  const commands = {
    users: "awk -F: '{print $1\":\"$3\":\"$7}' /etc/passwd 2>/dev/null || net user 2>nul",
    services: "systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null | awk '{print $1\":\"$2}' || sc query state= all 2>nul | findstr SERVICE_NAME",
    network: "ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' || netstat -tlnp 2>/dev/null | tail -n +3 | awk '{print $4}' || netstat -an 2>nul | findstr LISTENING",
    cron: "for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do c=$(crontab -l -u \"$u\" 2>/dev/null | grep -v '^#' | grep -v '^$'); [ -n \"$c\" ] && echo \"$u: $c\"; done; cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'; ls /etc/cron.d/ 2>/dev/null",
    processes: "ps -eo user,pid,comm --sort=-pcpu --no-headers 2>/dev/null | head -50 || tasklist /FO CSV /NH 2>nul | head -50"
  };

  const cmd = commands[checkType];
  if (!cmd) return {};

  try {
    const result = await saltClient.run({
      client: 'local',
      tgt: targets,
      fun: 'cmd.run',
      arg: [cmd],
      kwarg: { timeout: 30 }
    });
    return result || {};
  } catch (e) {
    logger.error(`Monitoring check ${checkType} failed`, e);
    return {};
  }
}

// Parse collected data into a comparable set of items
function parseCheckData(raw, checkType) {
  if (!raw || typeof raw !== 'string') return [];
  return raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
}

// ============================================================
// Diffing
// ============================================================

function diffItems(baselineItems, currentItems) {
  const baseSet = new Set(baselineItems);
  const currSet = new Set(currentItems);

  const added = currentItems.filter(i => !baseSet.has(i));
  const removed = baselineItems.filter(i => !currSet.has(i));

  return { added, removed };
}

function severityFor(checkType, changeType) {
  // users/cron changes = high, services/network new = high, processes = low
  if (checkType === 'users') return 'high';
  if (checkType === 'cron') return 'high';
  if (checkType === 'services' && changeType === 'added') return 'high';
  if (checkType === 'services' && changeType === 'removed') return 'medium';
  if (checkType === 'network' && changeType === 'added') return 'high';
  if (checkType === 'network' && changeType === 'removed') return 'medium';
  if (checkType === 'processes') return 'low';
  return 'medium';
}

// ============================================================
// Endpoints
// ============================================================

/**
 * POST /api/monitoring/baseline
 * Capture current state as a baseline
 */
router.post('/baseline', auditAction('monitoring.baseline'), async (req, res) => {
  const { name, targets, checks } = req.body;

  if (!targets) return res.status(400).json({ success: false, error: 'Targets required' });

  const checkTypes = (checks && checks.length > 0) ? checks.filter(c => CHECK_TYPES.includes(c)) : CHECK_TYPES;
  if (checkTypes.length === 0) return res.status(400).json({ success: false, error: 'No valid check types' });

  try {
    const data = {};
    for (const checkType of checkTypes) {
      data[checkType] = await collectCheck(targets, checkType);
    }

    const id = Date.now().toString(36) + Math.random().toString(36).substr(2, 4);
    baselines[id] = {
      id,
      name: name || `Baseline ${id}`,
      targets,
      checks: checkTypes,
      created: new Date().toISOString(),
      data // { checkType: { minion: rawString, ... } }
    };

    saveBaselines();
    res.json({ success: true, baseline: { id, name: baselines[id].name, targets, checks: checkTypes, created: baselines[id].created } });
  } catch (error) {
    logger.error('Failed to create baseline', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/monitoring/baselines
 * List all baselines (without data payloads)
 */
router.get('/baselines', (req, res) => {
  const list = Object.values(baselines).map(b => ({
    id: b.id,
    name: b.name,
    targets: b.targets,
    checks: b.checks,
    created: b.created
  }));
  res.json({ success: true, baselines: list });
});

/**
 * DELETE /api/monitoring/baselines/:id
 */
router.delete('/baselines/:id', auditAction('monitoring.delete_baseline'), (req, res) => {
  const { id } = req.params;
  if (!baselines[id]) return res.status(404).json({ success: false, error: 'Baseline not found' });
  delete baselines[id];
  saveBaselines();
  res.json({ success: true });
});

/**
 * POST /api/monitoring/check
 * Run a comparison against a baseline
 */
router.post('/check', auditAction('monitoring.check'), async (req, res) => {
  const { baselineId } = req.body;

  const baseline = baselines[baselineId];
  if (!baseline) return res.status(404).json({ success: false, error: 'Baseline not found' });

  try {
    const detectedChanges = [];

    for (const checkType of baseline.checks) {
      const currentData = await collectCheck(baseline.targets, checkType);

      for (const minion of Object.keys(currentData)) {
        const baselineRaw = baseline.data[checkType]?.[minion];
        const currentRaw = currentData[minion];

        const baseItems = parseCheckData(baselineRaw, checkType);
        const currItems = parseCheckData(currentRaw, checkType);

        const diff = diffItems(baseItems, currItems);

        if (diff.added.length > 0) {
          detectedChanges.push({
            timestamp: new Date().toISOString(),
            minion,
            checkType,
            changeType: 'added',
            severity: severityFor(checkType, 'added'),
            items: diff.added,
            baselineId
          });
        }
        if (diff.removed.length > 0) {
          detectedChanges.push({
            timestamp: new Date().toISOString(),
            minion,
            checkType,
            changeType: 'removed',
            severity: severityFor(checkType, 'removed'),
            items: diff.removed,
            baselineId
          });
        }
      }
    }

    // Persist changes
    changes.push(...detectedChanges);
    saveChanges();

    res.json({ success: true, changes: detectedChanges, total: detectedChanges.length });
  } catch (error) {
    logger.error('Monitoring check failed', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/monitoring/changes
 * Get detected changes (newest first)
 */
router.get('/changes', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  const sorted = [...changes].reverse().slice(0, limit);
  res.json({ success: true, changes: sorted, total: changes.length });
});

/**
 * POST /api/monitoring/schedule
 * Create an interval-based monitoring check
 */
router.post('/schedule', auditAction('monitoring.schedule'), (req, res) => {
  const { baselineId, intervalMinutes, name } = req.body;

  if (!baselineId) return res.status(400).json({ success: false, error: 'baselineId required' });
  if (!baselines[baselineId]) return res.status(404).json({ success: false, error: 'Baseline not found' });
  if (!intervalMinutes || intervalMinutes < 1) return res.status(400).json({ success: false, error: 'intervalMinutes must be >= 1' });

  const baseline = baselines[baselineId];

  const scheduleId = scheduler.create({
    name: name || `Monitor ${baseline.name}`,
    targets: baseline.targets,
    checks: baseline.checks,
    intervalMinutes,
    baselineId,
    callback: async (id) => {
      // Run the check
      try {
        const detectedChanges = [];
        for (const checkType of baseline.checks) {
          const currentData = await collectCheck(baseline.targets, checkType);
          for (const minion of Object.keys(currentData)) {
            const baselineRaw = baseline.data[checkType]?.[minion];
            const currentRaw = currentData[minion];
            const baseItems = parseCheckData(baselineRaw, checkType);
            const currItems = parseCheckData(currentRaw, checkType);
            const diff = diffItems(baseItems, currItems);
            if (diff.added.length > 0) {
              detectedChanges.push({
                timestamp: new Date().toISOString(),
                minion,
                checkType,
                changeType: 'added',
                severity: severityFor(checkType, 'added'),
                items: diff.added,
                baselineId,
                scheduleId: id
              });
            }
            if (diff.removed.length > 0) {
              detectedChanges.push({
                timestamp: new Date().toISOString(),
                minion,
                checkType,
                changeType: 'removed',
                severity: severityFor(checkType, 'removed'),
                items: diff.removed,
                baselineId,
                scheduleId: id
              });
            }
          }
        }
        changes.push(...detectedChanges);
        saveChanges();
        scheduler.markRun(id);
      } catch (e) {
        logger.error(`Scheduled check ${id} failed`, e);
      }
    }
  });

  res.json({ success: true, scheduleId, message: `Schedule created: every ${intervalMinutes} min` });
});

/**
 * GET /api/monitoring/schedules
 * List active schedules
 */
router.get('/schedules', (req, res) => {
  res.json({ success: true, schedules: scheduler.list() });
});

/**
 * DELETE /api/monitoring/schedules/:id
 */
router.delete('/schedules/:id', auditAction('monitoring.delete_schedule'), (req, res) => {
  const deleted = scheduler.delete(req.params.id);
  if (!deleted) return res.status(404).json({ success: false, error: 'Schedule not found' });
  res.json({ success: true });
});

module.exports = router;
