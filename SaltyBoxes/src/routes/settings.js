/**
 * Settings Routes
 *
 * Handles application and Salt API configuration.
 *
 * @module routes/settings
 */

const express = require('express');
const router = express.Router();
const {
  getAppConfig,
  getSaltConfig,
  saveSaltConfig,
  checkConfigFiles
} = require('../lib/config');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// Apply authentication to all settings routes
router.use(requireAuth);

/**
 * GET /api/settings
 * Get current settings (passwords masked)
 */
router.get('/', (req, res) => {
  try {
    const appConfig = getAppConfig();
    const saltConfig = getSaltConfig();

    // Mask sensitive values
    const safeSettings = {
      app: {
        server: appConfig.server,
        session: {
          timeout_minutes: appConfig.session.timeout_minutes
          // Don't expose session secret
        },
        logging: appConfig.logging,
        defaults: appConfig.defaults
      },
      salt: {
        api: {
          url: saltConfig.api.url,
          eauth: saltConfig.api.eauth,
          username: saltConfig.api.username,
          password: saltConfig.api.password ? '********' : '',
          verify_ssl: saltConfig.api.verify_ssl
        },
        defaults: saltConfig.defaults
      },
      configStatus: checkConfigFiles()
    };

    res.json({
      success: true,
      settings: safeSettings
    });
  } catch (error) {
    logger.error('Failed to get settings', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve settings'
    });
  }
});

/**
 * POST /api/settings/salt
 * Update Salt API configuration
 */
router.post('/salt', requireAdmin, async (req, res) => {
  const {
    url,
    username,
    password,
    eauth,
    verify_ssl
  } = req.body;

  try {
    const currentConfig = getSaltConfig();
    const newConfig = { ...currentConfig };

    // Update only provided values
    if (url !== undefined) {
      newConfig.api.url = url;
    }
    if (username !== undefined) {
      newConfig.api.username = username;
    }
    if (password !== undefined && password !== '********') {
      newConfig.api.password = password;
    }
    if (eauth !== undefined) {
      newConfig.api.eauth = eauth;
    }
    if (verify_ssl !== undefined) {
      newConfig.api.verify_ssl = verify_ssl;
    }

    saveSaltConfig(newConfig);

    // Reload the salt client with new settings
    saltClient.reload();

    logger.info('Salt API settings updated');

    res.json({
      success: true,
      message: 'Salt API settings updated'
    });
  } catch (error) {
    logger.error('Failed to update Salt settings', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update settings'
    });
  }
});

/**
 * POST /api/settings/salt/test
 * Test Salt API connection
 */
router.post('/salt/test', async (req, res) => {
  const {
    url,
    username,
    password,
    eauth,
    verify_ssl
  } = req.body;

  // Use provided values or current config
  const currentConfig = getSaltConfig();
  const testConfig = {
    url: url || currentConfig.api.url,
    username: username || currentConfig.api.username,
    password: (password && password !== '********') ? password : currentConfig.api.password,
    eauth: eauth || currentConfig.api.eauth,
    verify_ssl: verify_ssl !== undefined ? verify_ssl : currentConfig.api.verify_ssl
  };

  try {
    // Create a temporary client for testing
    const { SaltAPIClient } = require('../lib/salt-client');
    const testClient = new SaltAPIClient(testConfig);

    const startTime = Date.now();
    const connected = await testClient.testConnection();
    const responseTime = Date.now() - startTime;

    if (connected) {
      // Try to get some basic info
      let minionCount = 0;
      try {
        const status = await testClient.status();
        minionCount = (status.up || []).length + (status.down || []).length;
      } catch (e) {
        // Ignore - might not have permissions
      }

      res.json({
        success: true,
        connected: true,
        message: 'Connection successful',
        details: {
          url: testConfig.url,
          responseTime: responseTime,
          minionCount
        }
      });
    } else {
      res.json({
        success: true,
        connected: false,
        message: 'Connection failed - check credentials'
      });
    }
  } catch (error) {
    logger.error('Salt connection test failed', error);
    res.json({
      success: true,
      connected: false,
      message: 'Connection failed',
      error: error.message
    });
  }
});

/**
 * GET /api/settings/status
 * Get system status and configuration status
 */
router.get('/status', async (req, res) => {
  const configStatus = checkConfigFiles();
  const appConfig = getAppConfig();

  let saltStatus = {
    connected: false,
    url: null,
    error: null
  };

  try {
    const connected = await saltClient.testConnection();
    saltStatus = {
      connected,
      url: saltClient.baseUrl
    };

    if (connected) {
      const status = await saltClient.status();
      saltStatus.minions = {
        online: (status.up || []).length,
        offline: (status.down || []).length
      };
    }
  } catch (error) {
    saltStatus.error = error.message;
  }

  res.json({
    success: true,
    status: {
      server: {
        uptime: process.uptime(),
        nodeVersion: process.version,
        platform: process.platform,
        memory: process.memoryUsage()
      },
      config: configStatus,
      salt: saltStatus,
      session: {
        timeout_minutes: appConfig.session.timeout_minutes
      }
    }
  });
});

module.exports = router;
