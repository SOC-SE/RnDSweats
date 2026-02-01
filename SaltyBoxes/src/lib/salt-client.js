/**
 * Salt API Client
 *
 * Handles all communication with the Salt Master API.
 * Manages authentication tokens, request formatting, and response parsing.
 *
 * @module lib/salt-client
 */

const axios = require('axios');
const https = require('https');
const { getSaltConfig } = require('./config');
const logger = require('./logger');

/**
 * Salt API Client class
 * Manages connection to Salt Master and executes commands
 */
class SaltAPIClient {
  /**
   * Create a Salt API Client
   * @param {Object} [options] - Override default configuration
   * @param {string} [options.url] - Salt API URL
   * @param {string} [options.username] - Username for authentication
   * @param {string} [options.password] - Password for authentication
   * @param {string} [options.eauth] - Authentication backend (pam, ldap, etc.)
   * @param {boolean} [options.verify_ssl] - Verify SSL certificates
   */
  constructor(options = {}) {
    // Cache for minion kernel types (minion_id -> kernel)
    this.kernelCache = new Map();
    this.kernelCacheTimeout = 5 * 60 * 1000; // 5 minutes
    this.kernelCacheTimestamps = new Map();
    // Cache for domain controller detection (minion_id -> boolean)
    this.dcCache = new Map();
    this.dcCacheTimestamps = new Map();
    this.reload(options);
  }

  /**
   * Reload configuration from disk or apply new options
   * @param {Object} [options] - Override configuration
   */
  reload(options = {}) {
    const config = getSaltConfig();

    this.baseUrl = options.url || config.api.url;
    this.username = options.username || config.api.username;
    this.password = options.password || config.api.password;
    this.eauth = options.eauth || config.api.eauth;
    this.verifySsl = options.verify_ssl ?? config.api.verify_ssl ?? false;
    this.defaultTimeout = (config.defaults?.timeout || 30) * 1000;

    // Clear existing token on reload
    this.token = null;
    this.tokenExpiry = null;

    // Create axios instance with appropriate settings
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      httpsAgent: this.baseUrl.startsWith('https://') ?
        new https.Agent({ rejectUnauthorized: this.verifySsl }) : undefined
    });

    logger.debug(`Salt client configured for ${this.baseUrl}`);
  }

  /**
   * Authenticate with the Salt API and obtain a token
   * @returns {Promise<string>} Authentication token
   * @throws {Error} If authentication fails
   */
  async authenticate() {
    logger.debug('Authenticating with Salt API');

    try {
      const response = await this.client.post('/login', {
        username: this.username,
        password: this.password,
        eauth: this.eauth
      }, {
        timeout: 10000
      });

      const auth = response.data.return?.[0];
      if (!auth?.token) {
        throw new Error('No token received from Salt API');
      }

      this.token = auth.token;
      // Token expiry is in seconds since epoch
      this.tokenExpiry = auth.expire * 1000;

      logger.info(`Authenticated as ${this.username} (expires: ${new Date(this.tokenExpiry).toISOString()})`);
      return this.token;
    } catch (error) {
      const message = error.response?.data?.return?.[0] || error.message;
      logger.error('Salt API authentication failed', { message });
      throw new Error(`Authentication failed: ${message}`);
    }
  }

  /**
   * Ensure we have a valid authentication token
   * Re-authenticates if token is missing or about to expire
   * @returns {Promise<void>}
   */
  async ensureAuthenticated() {
    const now = Date.now();
    const bufferTime = 60000; // Re-auth 1 minute before expiry

    if (!this.token || !this.tokenExpiry || now >= this.tokenExpiry - bufferTime) {
      await this.authenticate();
    }
  }

  /**
   * Execute a Salt API request
   * Uses direct credential passing instead of token-based auth for better compatibility
   * with sharedsecret authentication.
   * @param {Object} options - Request options
   * @param {string} options.client - Salt client (local, wheel, runner, local_async)
   * @param {string} options.fun - Salt function to call
   * @param {string|string[]} [options.tgt] - Target minions
   * @param {string} [options.tgt_type='glob'] - Targeting type (glob, list, grain, compound)
   * @param {Array} [options.arg] - Positional arguments
   * @param {Object} [options.kwarg] - Keyword arguments
   * @param {number} [options.timeout] - Request timeout in ms
   * @returns {Promise<Object>} Salt API response
   */
  async run(options) {
    const {
      client,
      fun,
      tgt,
      tgt_type = 'glob',
      arg = [],
      kwarg = {},
      timeout = this.defaultTimeout
    } = options;

    // Include credentials directly in payload instead of using token
    const payload = {
      client,
      fun,
      username: this.username,
      password: this.password,
      eauth: this.eauth,
      ...(tgt !== undefined && { tgt }),
      ...(tgt !== undefined && { tgt_type }),
      ...(arg.length > 0 && { arg }),
      // Wheel and runner clients expect kwargs as top-level fields, not nested in kwarg
      ...(Object.keys(kwarg).length > 0 && (client === 'wheel' || client === 'runner' ? kwarg : { kwarg }))
    };

    logger.debug(`Salt API call: ${client}.${fun}`, { tgt, tgt_type });

    const maxRetries = 2;
    const retryDelays = [1000, 2000];
    const retryableCodes = new Set(['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND']);
    const retryableStatuses = new Set([502, 503, 504]);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await this.client.post('/run', payload, {
          timeout
        });

        const result = response.data.return?.[0];

        // Wheel and runner clients return data in a nested format when using direct credentials
        // Format: {"return": [{"tag": "...", "data": {"return": {...actual data...}}}]}
        if (result?.data?.return !== undefined) {
          return result.data.return;
        }

        return result || {};
      } catch (error) {
        const errCode = error.code;
        const status = error.response?.status;
        const isRetryable = retryableCodes.has(errCode) || retryableStatuses.has(status);

        if (isRetryable && attempt < maxRetries) {
          const delay = retryDelays[attempt];
          logger.warn(`Salt API call ${fun} failed (${errCode || status}), retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`);
          await new Promise(r => setTimeout(r, delay));
          continue;
        }

        const message = error.response?.data?.return?.[0] || error.message;
        logger.error(`Salt API error: ${fun}`, { message, status });
        throw new Error(`Salt API error: ${message}`);
      }
    }
  }

  // ============================================================
  // Convenience Methods - Test & Status
  // ============================================================

  /**
   * Ping minions to check connectivity
   * @param {string} [target='*'] - Target pattern
   * @returns {Promise<Object>} Map of minion_id -> true/false
   */
  async ping(target = '*') {
    return this.run({
      client: 'local',
      fun: 'test.ping',
      tgt: target
    });
  }

  /**
   * Get minion status (up/down)
   * @returns {Promise<{up: string[], down: string[]}>} Status object
   */
  async status() {
    const result = await this.run({
      client: 'runner',
      fun: 'manage.status'
    });
    return {
      up: result?.up || [],
      down: result?.down || []
    };
  }

  /**
   * Get kernel type for a minion (with caching)
   * @param {string} target - Minion ID
   * @returns {Promise<string>} Kernel type ('Linux' or 'Windows')
   */
  async getKernel(target) {
    const now = Date.now();
    const cacheTimestamp = this.kernelCacheTimestamps.get(target) || 0;

    // Return cached value if still valid
    if (this.kernelCache.has(target) && (now - cacheTimestamp) < this.kernelCacheTimeout) {
      return this.kernelCache.get(target);
    }

    // Fetch kernel from grains
    try {
      const result = await this.run({
        client: 'local',
        tgt: target,
        fun: 'grains.item',
        arg: ['kernel']
      });

      const kernel = result[target]?.kernel || 'Linux';
      this.kernelCache.set(target, kernel);
      this.kernelCacheTimestamps.set(target, now);
      return kernel;
    } catch (error) {
      logger.warn(`Failed to get kernel for ${target}, assuming Linux`);
      return 'Linux';
    }
  }

  /**
   * Get kernel type for multiple minions
   * @param {string} targets - Target expression (glob, list, etc.)
   * @returns {Promise<Object>} Map of minion_id -> kernel type
   */
  async getKernels(targets) {
    try {
      const result = await this.run({
        client: 'local',
        tgt: targets,
        tgt_type: Array.isArray(targets) ? 'list' : 'glob',
        fun: 'grains.item',
        arg: ['kernel']
      });

      const kernels = {};
      const now = Date.now();
      for (const [minion, data] of Object.entries(result || {})) {
        const kernel = data?.kernel || 'Linux';
        kernels[minion] = kernel;
        this.kernelCache.set(minion, kernel);
        this.kernelCacheTimestamps.set(minion, now);
      }
      return kernels;
    } catch (error) {
      logger.warn(`Failed to get kernels for ${targets}: ${error.message}`);
      return {};
    }
  }

  /**
   * Pre-populate kernel cache from devices data
   * @param {Object} devicesData - Map of minion_id -> device info with kernel
   */
  populateKernelCache(devicesData) {
    const now = Date.now();
    for (const [minionId, data] of Object.entries(devicesData)) {
      if (data.kernel) {
        this.kernelCache.set(minionId, data.kernel);
        this.kernelCacheTimestamps.set(minionId, now);
      }
    }
  }

  /**
   * Check if a Windows minion is a Domain Controller (with caching)
   * ProductType 2 = Domain Controller
   * @param {string} target - Minion ID
   * @returns {Promise<boolean>} True if DC
   */
  async isDomainController(target) {
    const now = Date.now();
    const cacheTimestamp = this.dcCacheTimestamps.get(target) || 0;

    if (this.dcCache.has(target) && (now - cacheTimestamp) < this.kernelCacheTimeout) {
      return this.dcCache.get(target);
    }

    try {
      const result = await this.run({
        client: 'local',
        fun: 'cmd.run',
        tgt: target,
        kwarg: {
          cmd: '(Get-WmiObject Win32_OperatingSystem).ProductType',
          shell: 'powershell',
          timeout: 15
        }
      });

      const productType = parseInt(result[target], 10);
      const isDC = productType === 2;
      this.dcCache.set(target, isDC);
      this.dcCacheTimestamps.set(target, now);
      return isDC;
    } catch (error) {
      logger.warn(`Failed to detect DC status for ${target}, assuming non-DC`);
      return false;
    }
  }

  /**
   * Pre-populate DC cache from external data
   * @param {Object} data - Map of minion_id -> boolean (isDC)
   */
  populateDCCache(data) {
    const now = Date.now();
    for (const [minionId, isDC] of Object.entries(data)) {
      this.dcCache.set(minionId, isDC);
      this.dcCacheTimestamps.set(minionId, now);
    }
  }

  /**
   * List all minion keys
   * @returns {Promise<Object>} Keys organized by status
   */
  async listKeys() {
    return this.run({
      client: 'wheel',
      fun: 'key.list_all'
    });
  }

  /**
   * Accept a minion key
   * @param {string} minionId - Minion ID to accept
   * @returns {Promise<Object>} Result
   */
  async acceptKey(minionId) {
    return this.run({
      client: 'wheel',
      fun: 'key.accept',
      kwarg: { match: minionId }
    });
  }

  /**
   * Delete a minion key
   * @param {string} minionId - Minion ID to delete
   * @returns {Promise<Object>} Result
   */
  async deleteKey(minionId) {
    return this.run({
      client: 'wheel',
      fun: 'key.delete',
      kwarg: { match: minionId }
    });
  }

  // ============================================================
  // Convenience Methods - Grains (System Information)
  // ============================================================

  /**
   * Get all grains for a target
   * @param {string} [target='*'] - Target pattern
   * @returns {Promise<Object>} Map of minion_id -> grains
   */
  async grains(target = '*') {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'grains.items',
      tgt: target,
      tgt_type
    });
  }

  /**
   * Get specific grain item(s)
   * @param {string} target - Target pattern
   * @param {string|string[]} items - Grain name(s) to retrieve
   * @returns {Promise<Object>} Map of minion_id -> grain values
   */
  async grainsItem(target, items) {
    const arg = Array.isArray(items) ? items : [items];
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'grains.item',
      tgt: target,
      tgt_type,
      arg
    });
  }

  // ============================================================
  // Convenience Methods - Command Execution
  // ============================================================

  /**
   * Run a shell command on targets
   * @param {string|string[]} target - Target pattern or list
   * @param {string} command - Command to execute
   * @param {Object} [options] - Additional options
   * @param {string} [options.shell] - Shell to use (Linux: /bin/bash, Windows: powershell)
   * @param {number} [options.timeout] - Command timeout in seconds
   * @param {string} [options.runas] - User to run command as
   * @param {string} [options.cwd] - Working directory
   * @returns {Promise<Object>} Map of minion_id -> output
   */
  async cmd(target, command, options = {}) {
    const {
      shell,
      timeout = 30,
      runas,
      cwd
    } = options;

    // Pass command via kwarg.cmd to avoid Salt misinterpreting '=' in
    // the command string as keyword arguments when sent via arg array.
    const kwarg = {
      cmd: command,
      python_shell: true,
      ...(shell && { shell }),
      ...(runas && { runas }),
      ...(cwd && { cwd }),
      timeout
    };

    // Single-element arrays should use glob (they may contain patterns like '*')
    const resolvedTarget = Array.isArray(target) && target.length === 1 ? target[0] : target;
    const tgt_type = Array.isArray(resolvedTarget) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: resolvedTarget,
      tgt_type,
      kwarg,
      timeout: (timeout + 10) * 1000 // HTTP timeout slightly longer
    });
  }

  /**
   * Execute a large script via cmd.script using a salt:// source or inline.
   * For very large commands that exceed cmd.run limits, this writes the script
   * content to a temp file on the minion via cp.recv then executes it.
   * Falls back to cmd.run with a wrapper that decodes base64 if cmd.script
   * is not suitable.
   * @param {string|string[]} target - Target pattern or list
   * @param {string} scriptContent - Full script content (bash)
   * @param {Object} [options] - Additional options (shell, timeout)
   * @returns {Promise<Object>} Map of minion_id -> output
   */
  async cmdScript(target, scriptContent, options = {}) {
    const { shell = '/bin/bash', timeout = 300 } = options;

    // Use cmd.run with stdin parameter to pipe the script content.
    // The command is a small wrapper; the actual script goes via kwarg.stdin
    // which Salt passes to the process's stdin, avoiding command-line length limits.
    const wrapper = `SCRIPT_FILE=$(mktemp /tmp/forensics_script_XXXXXX.sh) && cat > "$SCRIPT_FILE" && chmod +x "$SCRIPT_FILE" && ${shell} "$SCRIPT_FILE" 2>&1; RC=$?; rm -f "$SCRIPT_FILE"; exit $RC`;

    const resolvedTarget = Array.isArray(target) && target.length === 1 ? target[0] : target;
    const tgt_type = Array.isArray(resolvedTarget) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: resolvedTarget,
      tgt_type,
      kwarg: {
        cmd: wrapper,
        stdin: scriptContent,
        python_shell: true,
        shell,
        timeout
      },
      timeout: (timeout + 10) * 1000
    });
  }

  /**
   * Run a command with return code information
   * @param {string|string[]} target - Target pattern or list
   * @param {string} command - Command to execute
   * @param {Object} [options] - Additional options
   * @returns {Promise<Object>} Map of minion_id -> {retcode, stdout, stderr}
   */
  async cmdAll(target, command, options = {}) {
    const {
      shell,
      timeout = 30,
      runas,
      cwd
    } = options;

    const kwarg = {
      ...(shell && { shell }),
      ...(runas && { runas }),
      ...(cwd && { cwd }),
      timeout
    };

    const tgt_type = Array.isArray(target) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'cmd.run_all',
      tgt: target,
      tgt_type,
      arg: [command],
      kwarg,
      timeout: (timeout + 10) * 1000
    });
  }

  /**
   * Execute a script on targets
   * @param {string|string[]} target - Target pattern or list
   * @param {string} source - Script source (salt://, http://, or local path)
   * @param {Object} [options] - Additional options
   * @param {string} [options.args] - Arguments to pass to script
   * @param {string} [options.shell] - Shell to use
   * @param {number} [options.timeout] - Execution timeout
   * @returns {Promise<Object>} Map of minion_id -> output
   */
  async script(target, source, options = {}) {
    const {
      args = '',
      shell,
      timeout = 120
    } = options;

    const kwarg = {
      ...(shell && { shell }),
      timeout
    };

    const arg = args ? [source, args] : [source];
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'cmd.script',
      tgt: target,
      tgt_type,
      arg,
      kwarg,
      timeout: (timeout + 10) * 1000
    });
  }

  /**
   * Execute script content directly on targets
   * Uses cmd.run with the script content for inline execution
   * @param {string|string[]} target - Target pattern or list
   * @param {string} content - Script content to execute
   * @param {Object} [options] - Additional options
   * @param {string} [options.shell] - Shell to use (/bin/bash, powershell, cmd)
   * @param {string} [options.args] - Arguments to pass
   * @param {number} [options.timeout] - Execution timeout in seconds
   * @param {string} [options.runas] - User to run as
   * @returns {Promise<Object>} Map of minion_id -> output
   */
  async scriptContent(target, content, options = {}) {
    const {
      shell = '/bin/bash',
      args = '',
      timeout = 120,
      runas
    } = options;

    const tgt_type = Array.isArray(target) ? 'list' : 'glob';

    // Use stdin to pass script content to a temp file, avoiding command-line length limits.
    // This works for both bash and PowerShell scripts.
    let wrapper;
    if (shell === 'powershell' || shell === 'powershell.exe') {
      // PowerShell: read stdin, write to temp .ps1, execute, then clean up
      const argsStr = args ? ` ${args}` : '';
      wrapper = `powershell -Command "$f=[System.IO.Path]::GetTempPath()+'saltscript_'+[System.IO.Path]::GetRandomFileName()+'.ps1'; [System.IO.File]::WriteAllText($f,[Console]::In.ReadToEnd()); try { powershell -ExecutionPolicy Bypass -File $f${argsStr} } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }"`;

    } else {
      // Bash/sh: write stdin to a temp file, then execute it
      const argsStr = args ? ` ${args}` : '';
      wrapper = `SCRIPT_FILE=$(mktemp /tmp/salt_script_XXXXXX.sh) && cat > "$SCRIPT_FILE" && chmod +x "$SCRIPT_FILE" && ${shell} "$SCRIPT_FILE"${argsStr} 2>&1; RC=$?; rm -f "$SCRIPT_FILE"; exit $RC`;
    }

    const kwarg = {
      cmd: wrapper,
      stdin: content,
      python_shell: true,
      timeout,
      ...(runas && { runas })
    };

    return this.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: target,
      tgt_type,
      kwarg,
      timeout: (timeout + 10) * 1000
    });
  }

  // ============================================================
  // Convenience Methods - Service Management
  // ============================================================

  /**
   * List all services on targets
   * @param {string|string[]} target - Target pattern or list
   * @returns {Promise<Object>} Map of minion_id -> service list
   */
  async serviceGetAll(target) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.get_all',
      tgt: target,
      tgt_type
    });
  }

  /**
   * Get status of a specific service
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Map of minion_id -> boolean
   */
  async serviceStatus(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.status',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  /**
   * Start a service
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Result
   */
  async serviceStart(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.start',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  /**
   * Stop a service
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Result
   */
  async serviceStop(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.stop',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  /**
   * Restart a service
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Result
   */
  async serviceRestart(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.restart',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  /**
   * Enable a service at boot
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Result
   */
  async serviceEnable(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.enable',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  /**
   * Disable a service at boot
   * @param {string|string[]} target - Target pattern or list
   * @param {string} service - Service name
   * @returns {Promise<Object>} Result
   */
  async serviceDisable(target, service) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'service.disable',
      tgt: target,
      tgt_type,
      arg: [service]
    });
  }

  // ============================================================
  // Convenience Methods - Process Management
  // ============================================================

  /**
   * List top processes
   * @param {string|string[]} target - Target pattern or list
   * @param {number} [numProcs=50] - Number of processes to return
   * @returns {Promise<Object>} Map of minion_id -> process list
   */
  async psTop(target, numProcs = 50) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'ps.top',
      tgt: target,
      tgt_type,
      kwarg: { num_processes: numProcs }
    });
  }

  /**
   * Kill a process by PID
   * @param {string|string[]} target - Target pattern or list
   * @param {number} pid - Process ID
   * @param {number} [signal=15] - Signal to send (15=SIGTERM, 9=SIGKILL)
   * @returns {Promise<Object>} Result
   */
  async psKill(target, pid, signal = 15) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'ps.kill_pid',
      tgt: target,
      tgt_type,
      arg: [pid],
      kwarg: { signal }
    });
  }

  // ============================================================
  // Convenience Methods - User Management
  // ============================================================

  /**
   * List all users
   * @param {string|string[]} target - Target pattern or list
   * @returns {Promise<Object>} Map of minion_id -> user list
   */
  async userList(target) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'user.list_users',
      tgt: target,
      tgt_type
    });
  }

  /**
   * Get user info
   * @param {string|string[]} target - Target pattern or list
   * @param {string} username - Username
   * @returns {Promise<Object>} Map of minion_id -> user info
   */
  async userInfo(target, username) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'user.info',
      tgt: target,
      tgt_type,
      arg: [username]
    });
  }

  // ============================================================
  // Convenience Methods - Password Management
  // ============================================================

  /**
   * Change password on Linux (using chpasswd)
   * @param {string|string[]} target - Target Linux minions
   * @param {string} username - Username
   * @param {string} password - New password
   * @returns {Promise<Object>} Result
   */
  async setPasswordLinux(target, username, password) {
    // Use cmd.run with chpasswd for reliability
    const command = `echo '${username}:${password}' | chpasswd`;
    return this.cmd(target, command, { shell: '/bin/bash' });
  }

  /**
   * Change password on Windows
   * @param {string|string[]} target - Target Windows minions
   * @param {string} username - Username
   * @param {string} password - New password
   * @returns {Promise<Object>} Result
   */
  async setPasswordWindows(target, username, password) {
    // Use net user for compatibility, or PowerShell for local users
    const command = `net user "${username}" "${password}"`;
    return this.cmd(target, command, { shell: 'cmd' });
  }

  // ============================================================
  // Convenience Methods - Network
  // ============================================================

  /**
   * Get active TCP connections
   * @param {string|string[]} target - Target pattern or list
   * @returns {Promise<Object>} Map of minion_id -> connections
   */
  async networkConnections(target) {
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';
    return this.run({
      client: 'local',
      fun: 'network.active_tcp',
      tgt: target,
      tgt_type
    });
  }

  // ============================================================
  // Convenience Methods - State Management
  // ============================================================

  /**
   * Apply a Salt state
   * @param {string|string[]} target - Target pattern or list
   * @param {string} stateName - State to apply
   * @param {Object} [options] - Additional options
   * @param {boolean} [options.test=false] - Run in test mode (dry run)
   * @returns {Promise<Object>} Map of minion_id -> state results
   */
  async stateApply(target, stateName, options = {}) {
    const { test = false } = options;
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'state.apply',
      tgt: target,
      tgt_type,
      arg: [stateName],
      kwarg: test ? { test: true } : {},
      timeout: 600000 // States can take a while
    });
  }

  /**
   * Apply state from inline YAML content
   * @param {string|string[]} target - Target pattern or list
   * @param {string} stateContent - YAML state content
   * @param {Object} [options] - Additional options
   * @param {boolean} [options.test=false] - Run in test mode
   * @returns {Promise<Object>} Map of minion_id -> state results
   */
  async stateTemplateStr(target, stateContent, options = {}) {
    const { test = false } = options;
    const tgt_type = Array.isArray(target) ? 'list' : 'glob';

    return this.run({
      client: 'local',
      fun: 'state.template_str',
      tgt: target,
      tgt_type,
      arg: [stateContent],
      kwarg: test ? { test: true } : {},
      timeout: 600000
    });
  }

  // ============================================================
  // Convenience Methods - File Operations
  // ============================================================

  /**
   * Read a file from target
   * @param {string} target - Single target (not pattern)
   * @param {string} filePath - Path to file
   * @returns {Promise<string>} File contents
   */
  async fileRead(target, filePath) {
    const result = await this.run({
      client: 'local',
      fun: 'file.read',
      tgt: target,
      arg: [filePath]
    });
    return result[target];
  }

  /**
   * Get file stats
   * @param {string} target - Single target
   * @param {string} filePath - Path to file
   * @returns {Promise<Object>} File stats
   */
  async fileStats(target, filePath) {
    const result = await this.run({
      client: 'local',
      fun: 'file.stats',
      tgt: target,
      arg: [filePath]
    });
    return result[target];
  }

  // ============================================================
  // Async Job Management
  // ============================================================

  /**
   * Submit an async job
   * @param {Object} options - Same as run() options
   * @returns {Promise<string>} Job ID (jid)
   */
  async runAsync(options) {
    const result = await this.run({
      ...options,
      client: 'local_async'
    });
    return result?.jid;
  }

  /**
   * Look up results of an async job
   * @param {string} jid - Job ID
   * @returns {Promise<Object>} Job results
   */
  async jobLookup(jid) {
    return this.run({
      client: 'runner',
      fun: 'jobs.lookup_jid',
      kwarg: { jid }
    });
  }

  /**
   * Check if Salt API is reachable and credentials are valid
   * @returns {Promise<boolean>} True if reachable and authenticated
   */
  async testConnection() {
    try {
      // Use a simple wheel call to test connection and auth
      await this.run({
        client: 'wheel',
        fun: 'key.list_all',
        timeout: 10000
      });
      return true;
    } catch {
      return false;
    }
  }
}

// Export singleton instance and class
const defaultClient = new SaltAPIClient();

module.exports = {
  SaltAPIClient,
  client: defaultClient,
  // Re-export commonly used methods bound to default client
  ping: (...args) => defaultClient.ping(...args),
  status: (...args) => defaultClient.status(...args),
  cmd: (...args) => defaultClient.cmd(...args),
  grains: (...args) => defaultClient.grains(...args),
  listKeys: (...args) => defaultClient.listKeys(...args)
};
