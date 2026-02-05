/**
 * Log Viewer Routes
 *
 * Provides log viewing capabilities for minions.
 * Supports common log files on Linux and Windows.
 *
 * @module routes/logs
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all log routes
router.use(requireAuth);

// Windows event logs (always available)
const WINDOWS_EVENT_LOGS = [
  { name: 'System Events', type: 'event', log: 'System' },
  { name: 'Security Events', type: 'event', log: 'Security' },
  { name: 'Application Events', type: 'event', log: 'Application' }
];

/**
 * Build a display name from a log file path.
 * e.g. /var/log/nginx/access.log -> "nginx/access.log"
 *      /var/log/auth.log -> "auth.log"
 *      /var/log/salt/minion -> "salt/minion"
 */
function logDisplayName(filePath) {
  const prefix = '/var/log/';
  if (filePath.startsWith(prefix)) {
    return filePath.slice(prefix.length);
  }
  return filePath;
}

/**
 * GET /api/logs/sources
 * Dynamically discover available log files on a target
 */
router.get('/sources/:target', async (req, res) => {
  const { target } = req.params;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    const kernel = await saltClient.getKernel(target);

    if (kernel === 'Windows') {
      // For Windows, list event logs plus discover text log files
      const sources = [...WINDOWS_EVENT_LOGS];

      try {
        const command = `powershell -Command "Get-ChildItem -Path 'C:\\salt\\var\\log','C:\\Windows\\Logs' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | Select-Object -ExpandProperty FullName | Sort-Object"`;
        const result = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: [command],
          kwarg: { timeout: 15 }
        });

        const output = result[target];
        if (output && typeof output === 'string') {
          output.split('\n').filter(l => l.trim()).forEach(filePath => {
            sources.push({ name: filePath.trim(), path: filePath.trim() });
          });
        }
      } catch (e) {
        // If discovery fails, still return event logs
        logger.debug('Windows log file discovery failed', e.message);
      }

      return res.json({ success: true, target, kernel, sources });
    }

    // Linux: discover log files dynamically
    const command = `find /var/log -type f \\( -name '*.log' -o -name '*.log.*' -o -name 'syslog' -o -name 'syslog.*' -o -name 'messages' -o -name 'messages.*' -o -name 'secure' -o -name 'secure.*' -o -name 'auth.log' -o -name 'auth.log.*' -o -name 'cron' -o -name 'cron.*' -o -name 'kern.log' -o -name 'kern.log.*' -o -name 'dmesg' -o -name 'dmesg.*' -o -name 'minion' -o -name 'master' -o -name 'lastlog' -o -name 'faillog' -o -name 'btmp' -o -name 'wtmp' -o -name 'dpkg.log' -o -name 'yum.log' -o -name 'dnf.log' \\) -size +0c 2>/dev/null | sort`;

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 15 }
    });

    const output = result[target];
    const sources = [];

    if (output && typeof output === 'string') {
      const files = output.split('\n').filter(l => l.trim() && l.startsWith('/'));

      // Skip binary log files
      const binaryFiles = new Set(['lastlog', 'faillog', 'btmp', 'wtmp']);

      for (const filePath of files) {
        const basename = filePath.split('/').pop();
        if (binaryFiles.has(basename)) continue;

        sources.push({
          name: logDisplayName(filePath),
          path: filePath
        });
      }
    }

    // If discovery returned nothing, provide a minimal fallback
    if (sources.length === 0) {
      sources.push(
        { name: 'syslog', path: '/var/log/syslog' },
        { name: 'messages', path: '/var/log/messages' },
        { name: 'auth.log', path: '/var/log/auth.log' },
        { name: 'secure', path: '/var/log/secure' }
      );
    }

    res.json({ success: true, target, kernel, sources });

  } catch (error) {
    logger.error('Failed to get log sources', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get log sources',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/read
 * Read log file content
 *
 * Query params:
 *   path: string - Log file path
 *   lines: number - Number of lines to tail (default: 100)
 */
router.get('/:target/read', auditAction('logs.read'), async (req, res) => {
  const { target } = req.params;
  const { path, lines = 100 } = req.query;

  if (!target || !path) {
    return res.status(400).json({
      success: false,
      error: 'Target and path are required'
    });
  }

  const numLines = Math.min(Math.max(parseInt(lines, 10) || 100, 10), 1000);

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    let command;
    if (kernel === 'Windows') {
      // PowerShell to get last N lines
      command = `powershell -Command "Get-Content -Path '${path}' -Tail ${numLines} -ErrorAction SilentlyContinue"`;
    } else {
      // Linux tail
      command = `tail -n ${numLines} "${path}" 2>/dev/null`;
    }

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 30 }
    });

    const output = result[target];

    if (!output || typeof output !== 'string') {
      return res.json({
        success: true,
        target,
        path,
        lines: [],
        message: 'No output or file not found'
      });
    }

    const logLines = output.split('\n');

    res.json({
      success: true,
      target,
      path,
      kernel,
      lines: logLines,
      total: logLines.length
    });

  } catch (error) {
    logger.error('Failed to read log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read log',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/events
 * Read Windows event log
 *
 * Query params:
 *   log: string - Event log name (System, Security, Application)
 *   count: number - Number of events (default: 50)
 */
router.get('/:target/events', auditAction('logs.events'), async (req, res) => {
  const { target } = req.params;
  const { log = 'System', count = 50 } = req.query;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  const numEvents = Math.min(Math.max(parseInt(count, 10) || 50, 10), 200);

  try {
    // PowerShell command to get event log entries
    const command = `powershell -Command "Get-EventLog -LogName '${log}' -Newest ${numEvents} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json -Compress"`;

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 60 }
    });

    const output = result[target];

    if (!output || typeof output !== 'string') {
      return res.json({
        success: true,
        target,
        log,
        events: [],
        message: 'No events or access denied'
      });
    }

    let events = [];
    try {
      const parsed = JSON.parse(output);
      events = Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {
      // If not JSON, return as raw lines
      events = output.split('\n').map(line => ({ raw: line }));
    }

    res.json({
      success: true,
      target,
      log,
      events,
      total: events.length
    });

  } catch (error) {
    logger.error('Failed to read event log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read event log',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/search
 * Search log file for pattern
 *
 * Query params:
 *   path: string - Log file path
 *   pattern: string - Search pattern (grep-compatible)
 *   lines: number - Max lines to return (default: 100)
 */
router.get('/:target/search', auditAction('logs.search'), async (req, res) => {
  const { target } = req.params;
  const { path, pattern, lines = 100 } = req.query;

  if (!target || !path || !pattern) {
    return res.status(400).json({
      success: false,
      error: 'Target, path, and pattern are required'
    });
  }

  const numLines = Math.min(Math.max(parseInt(lines, 10) || 100, 10), 500);

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    let command;
    if (kernel === 'Windows') {
      command = `powershell -Command "Select-String -Path '${path}' -Pattern '${pattern}' | Select-Object -Last ${numLines} | ForEach-Object { $_.Line }"`;
    } else {
      command = `grep -i "${pattern}" "${path}" 2>/dev/null | tail -n ${numLines}`;
    }

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 30 }
    });

    const output = result[target];
    const matches = output ? output.split('\n').filter(l => l.trim()) : [];

    res.json({
      success: true,
      target,
      path,
      pattern,
      matches,
      total: matches.length
    });

  } catch (error) {
    logger.error('Failed to search log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to search log',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/tail
 * SSE endpoint for live log tailing
 *
 * Query params:
 *   path: string - Log file path
 *   lines: number - Number of lines per poll (default: 50)
 */
router.get('/:target/tail', async (req, res) => {
  const { target } = req.params;
  const { path: logPath, lines = 50 } = req.query;

  if (!target || !logPath) {
    return res.status(400).json({ success: false, error: 'Target and path are required' });
  }

  const numLines = Math.min(Math.max(parseInt(lines, 10) || 50, 10), 500);

  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  const sendEvent = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  let previousLines = [];
  const startTime = Date.now();
  const maxDuration = 30 * 60 * 1000; // 30 minutes
  const pollInterval = 2000;
  let stopped = false;

  sendEvent('status', { status: 'streaming', target, path: logPath });

  // Determine kernel for OS-appropriate tail command
  let kernel = 'Linux';
  try {
    kernel = await saltClient.getKernel(target);
  } catch {}

  const poll = setInterval(async () => {
    if (stopped) return;

    try {
      if (Date.now() - startTime > maxDuration) {
        sendEvent('status', { status: 'timeout' });
        clearInterval(poll);
        res.end();
        return;
      }

      let command;
      if (kernel === 'Windows') {
        command = `powershell -Command "Get-Content -Path '${logPath}' -Tail ${numLines} -ErrorAction SilentlyContinue"`;
      } else {
        command = `tail -n ${numLines} "${logPath}" 2>/dev/null`;
      }

      const result = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'cmd.run',
        arg: [command],
        kwarg: { timeout: 10 }
      });

      const output = result[target];
      if (!output || typeof output !== 'string') return;

      const currentLines = output.split('\n');

      // Find new lines by comparing with previous snapshot
      if (previousLines.length === 0) {
        // First poll - send all lines
        sendEvent('lines', { lines: currentLines });
      } else {
        // Find where previous content ends in current content
        const lastPrev = previousLines[previousLines.length - 1];
        let newStartIdx = -1;

        // Search backwards from end of current for last known previous line
        for (let i = currentLines.length - 1; i >= 0; i--) {
          if (currentLines[i] === lastPrev) {
            newStartIdx = i + 1;
            break;
          }
        }

        if (newStartIdx > 0 && newStartIdx < currentLines.length) {
          const newLines = currentLines.slice(newStartIdx);
          if (newLines.length > 0) {
            sendEvent('lines', { lines: newLines });
          }
        } else if (newStartIdx === -1) {
          // Content changed completely, send all
          sendEvent('lines', { lines: currentLines });
        }
        // If newStartIdx === currentLines.length, no new lines
      }

      previousLines = currentLines;

    } catch (error) {
      sendEvent('error', { message: error.message });
    }
  }, pollInterval);

  // Clean up on client disconnect
  req.on('close', () => {
    stopped = true;
    clearInterval(poll);
  });
});

module.exports = router;
