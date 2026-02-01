/**
 * Network Routes
 *
 * Provides network connection information from minions.
 * Uses Salt's network module for connection data.
 *
 * @module routes/network
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all network routes
router.use(requireAuth);

/**
 * GET /api/network/:target
 * Get network connections for a target minion
 *
 * Query params:
 *   type: string - Connection type (tcp, udp, all) - default: all
 *   state: string - Connection state filter (LISTEN, ESTABLISHED, etc.)
 */
router.get('/:target', auditAction('network.list'), async (req, res) => {
  const { target } = req.params;
  const { type = 'all', state } = req.query;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    // Use cmd.run with ss/netstat for more reliable output
    // ss is preferred on Linux, but fallback to netstat for Windows
    let command;

    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    if (kernel === 'Windows') {
      // Windows netstat
      command = 'netstat -an';
    } else {
      // Linux ss command (more detailed than netstat)
      let ssFlags = '-tunap';
      if (type === 'tcp') ssFlags = '-tnap';
      else if (type === 'udp') ssFlags = '-unap';

      command = `ss ${ssFlags} 2>/dev/null || netstat -${ssFlags.replace('a', '')} 2>/dev/null`;
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
        connections: [],
        raw: output
      });
    }

    // Parse the output
    const connections = parseNetworkOutput(output, kernel, state);

    res.json({
      success: true,
      target,
      kernel,
      connections,
      total: connections.length
    });

  } catch (error) {
    logger.error('Failed to get network connections', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get network connections',
      details: error.message
    });
  }
});

/**
 * GET /api/network/:target/listening
 * Get listening ports on a target minion
 */
router.get('/:target/listening', auditAction('network.listening'), async (req, res) => {
  const { target } = req.params;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    // Determine OS first
    const grainsResult = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'grains.item',
      arg: ['kernel']
    });

    const kernel = grainsResult[target]?.kernel || 'Linux';

    let command;
    if (kernel === 'Windows') {
      command = 'netstat -an | findstr LISTENING';
    } else {
      command = 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null';
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
        listening: [],
        raw: output
      });
    }

    // Parse listening ports
    const listening = parseListeningPorts(output, kernel);

    res.json({
      success: true,
      target,
      kernel,
      listening,
      total: listening.length
    });

  } catch (error) {
    logger.error('Failed to get listening ports', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get listening ports',
      details: error.message
    });
  }
});

/**
 * Parse network output from ss or netstat
 */
function parseNetworkOutput(output, kernel, stateFilter) {
  const connections = [];
  const lines = output.split('\n').filter(l => l.trim());

  if (kernel === 'Windows') {
    // Windows netstat format: Proto  Local Address  Foreign Address  State
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4 && (parts[0] === 'TCP' || parts[0] === 'UDP')) {
        const conn = {
          protocol: parts[0].toLowerCase(),
          local: parts[1],
          remote: parts[2],
          state: parts[3] || 'UNKNOWN'
        };

        if (!stateFilter || conn.state.toUpperCase().includes(stateFilter.toUpperCase())) {
          connections.push(conn);
        }
      }
    }
  } else {
    // Linux ss format
    // State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
    for (const line of lines) {
      if (line.startsWith('Netid') || line.startsWith('State') || line.startsWith('Proto')) {
        continue; // Skip header lines
      }

      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5) {
        // ss output format
        let state, local, remote, process;

        if (parts[0] === 'tcp' || parts[0] === 'udp') {
          // Netid State format
          state = parts[1];
          local = parts[4];
          remote = parts[5];
          process = parts.slice(6).join(' ');
        } else if (parts[0].match(/^(LISTEN|ESTAB|TIME-WAIT|CLOSE-WAIT)/)) {
          // State format
          state = parts[0];
          local = parts[3];
          remote = parts[4];
          process = parts.slice(5).join(' ');
        } else {
          continue;
        }

        // Extract process name from users:(("name",pid=123,fd=4))
        let processName = '';
        const processMatch = process.match(/users:\(\("([^"]+)"/);
        if (processMatch) {
          processName = processMatch[1];
        }

        const conn = {
          protocol: parts[0] === 'tcp' || parts[0] === 'udp' ? parts[0] : 'tcp',
          state: state.replace('ESTAB', 'ESTABLISHED'),
          local,
          remote,
          process: processName
        };

        if (!stateFilter || conn.state.toUpperCase().includes(stateFilter.toUpperCase())) {
          connections.push(conn);
        }
      }
    }
  }

  return connections;
}

/**
 * Parse listening ports output
 */
function parseListeningPorts(output, kernel) {
  const listening = [];
  const lines = output.split('\n').filter(l => l.trim());

  if (kernel === 'Windows') {
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4 && parts[0] === 'TCP' && parts[3] === 'LISTENING') {
        const [ip, port] = parts[1].split(':');
        listening.push({
          protocol: 'tcp',
          address: ip,
          port: port,
          process: ''
        });
      }
    }
  } else {
    // Linux ss/netstat output
    for (const line of lines) {
      if (line.startsWith('State') || line.startsWith('Proto') || line.startsWith('Netid')) {
        continue;
      }

      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        let local, process = '';

        // ss format: State Recv-Q Send-Q Local Remote Process
        // or: Netid State Recv-Q Send-Q Local Remote Process
        if (parts[0] === 'LISTEN' || parts[0] === 'tcp' || parts[0] === 'udp') {
          if (parts[0] === 'LISTEN') {
            local = parts[3];
            process = parts.slice(5).join(' ');
          } else {
            local = parts[4];
            process = parts.slice(6).join(' ');
          }
        } else if (parts[0].match(/^tcp|^udp/)) {
          // netstat format
          local = parts[3];
          process = parts[parts.length - 1];
        } else {
          continue;
        }

        // Parse address:port
        const lastColon = local.lastIndexOf(':');
        if (lastColon > 0) {
          const address = local.substring(0, lastColon);
          const port = local.substring(lastColon + 1);

          // Extract process name
          let processName = '';
          const processMatch = process.match(/users:\(\("([^"]+)"/);
          if (processMatch) {
            processName = processMatch[1];
          } else if (process && !process.includes('users:')) {
            processName = process;
          }

          listening.push({
            protocol: 'tcp',
            address,
            port,
            process: processName
          });
        }
      }
    }
  }

  return listening;
}

module.exports = router;
