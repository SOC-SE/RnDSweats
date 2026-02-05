/**
 * Configuration Loader
 *
 * Loads and validates YAML configuration files.
 * Supports environment variable overrides for sensitive values.
 *
 * @module lib/config
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Configuration file paths
const CONFIG_DIR = process.env.SALT_GUI_CONFIG_DIR || path.join(__dirname, '../../config');
const APP_CONFIG_PATH = path.join(CONFIG_DIR, 'app.yaml');
const AUTH_CONFIG_PATH = path.join(CONFIG_DIR, 'auth.yaml');
const SALT_CONFIG_PATH = path.join(CONFIG_DIR, 'salt.yaml');

// Default configurations
const DEFAULT_APP_CONFIG = {
  server: {
    port: 3000,
    host: '0.0.0.0'
  },
  session: {
    timeout_minutes: 30,
    secret: null // Will be auto-generated
  },
  logging: {
    level: 'info',
    audit_file: 'logs/audit.yaml'
  },
  defaults: {
    command_timeout: 30,
    script_timeout: 120
  }
};

const DEFAULT_SALT_CONFIG = {
  api: {
    url: 'https://127.0.0.1:8001',
    eauth: 'pam',
    username: '',
    password: '',
    verify_ssl: false
  },
  defaults: {
    timeout: 30,
    batch_size: 10
  }
};

const DEFAULT_AUTH_CONFIG = {
  users: {}
};

/**
 * Load a YAML configuration file
 * @param {string} filePath - Path to the YAML file
 * @param {Object} defaults - Default values if file doesn't exist
 * @returns {Object} Parsed configuration
 */
function loadYamlConfig(filePath, defaults = {}) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = yaml.load(content) || {};
      return deepMerge(defaults, parsed);
    }
  } catch (error) {
    console.error(`[Config] Error loading ${filePath}: ${error.message}`);
  }
  return { ...defaults };
}

/**
 * Deep merge two objects
 * @param {Object} target - Target object
 * @param {Object} source - Source object to merge
 * @returns {Object} Merged object
 */
function deepMerge(target, source) {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }

  return result;
}

/**
 * Save configuration to YAML file
 * @param {string} filePath - Path to save to
 * @param {Object} config - Configuration object
 */
function saveYamlConfig(filePath, config) {
  const content = yaml.dump(config, {
    indent: 2,
    lineWidth: 120,
    noRefs: true
  });

  // Ensure directory exists
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(filePath, content, 'utf8');
}

// Cached configurations
let appConfig = null;
let saltConfig = null;
let authConfig = null;

/**
 * Get application configuration
 * @param {boolean} reload - Force reload from disk
 * @returns {Object} Application configuration
 */
function getAppConfig(reload = false) {
  if (!appConfig || reload) {
    appConfig = loadYamlConfig(APP_CONFIG_PATH, DEFAULT_APP_CONFIG);

    // Environment variable overrides
    if (process.env.SALT_GUI_PORT) {
      appConfig.server.port = parseInt(process.env.SALT_GUI_PORT, 10);
    }
    if (process.env.SALT_GUI_HOST) {
      appConfig.server.host = process.env.SALT_GUI_HOST;
    }
    if (process.env.SALT_GUI_SESSION_SECRET) {
      appConfig.session.secret = process.env.SALT_GUI_SESSION_SECRET;
    }
    if (process.env.SALT_GUI_LOG_LEVEL) {
      appConfig.logging.level = process.env.SALT_GUI_LOG_LEVEL;
    }
  }
  return appConfig;
}

/**
 * Get Salt API configuration
 * @param {boolean} reload - Force reload from disk
 * @returns {Object} Salt API configuration
 */
function getSaltConfig(reload = false) {
  if (!saltConfig || reload) {
    saltConfig = loadYamlConfig(SALT_CONFIG_PATH, DEFAULT_SALT_CONFIG);

    // Environment variable overrides (higher priority)
    if (process.env.SALT_API_URL) {
      saltConfig.api.url = process.env.SALT_API_URL;
    }
    if (process.env.SALT_API_USERNAME) {
      saltConfig.api.username = process.env.SALT_API_USERNAME;
    }
    if (process.env.SALT_API_PASSWORD) {
      saltConfig.api.password = process.env.SALT_API_PASSWORD;
    }
    if (process.env.SALT_API_EAUTH) {
      saltConfig.api.eauth = process.env.SALT_API_EAUTH;
    }
  }
  return saltConfig;
}

/**
 * Get authentication configuration
 * @param {boolean} reload - Force reload from disk
 * @returns {Object} Authentication configuration
 */
function getAuthConfig(reload = false) {
  if (!authConfig || reload) {
    authConfig = loadYamlConfig(AUTH_CONFIG_PATH, DEFAULT_AUTH_CONFIG);
  }
  return authConfig;
}

/**
 * Save authentication configuration
 * @param {Object} config - New auth configuration
 */
function saveAuthConfig(config) {
  authConfig = config;
  saveYamlConfig(AUTH_CONFIG_PATH, config);
}

/**
 * Save Salt API configuration
 * @param {Object} config - New Salt configuration
 */
function saveSaltConfig(config) {
  saltConfig = config;
  saveYamlConfig(SALT_CONFIG_PATH, config);
}

/**
 * Check if configuration files exist
 * @returns {Object} Status of each config file
 */
function checkConfigFiles() {
  return {
    app: fs.existsSync(APP_CONFIG_PATH),
    salt: fs.existsSync(SALT_CONFIG_PATH),
    auth: fs.existsSync(AUTH_CONFIG_PATH)
  };
}

/**
 * Get configuration directory path
 * @returns {string} Path to config directory
 */
function getConfigDir() {
  return CONFIG_DIR;
}

/**
 * Reload all configurations from disk
 */
function reloadAll() {
  getAppConfig(true);
  getSaltConfig(true);
  getAuthConfig(true);
}

module.exports = {
  getAppConfig,
  getSaltConfig,
  getAuthConfig,
  saveAuthConfig,
  saveSaltConfig,
  checkConfigFiles,
  getConfigDir,
  reloadAll,
  // For testing
  loadYamlConfig,
  saveYamlConfig,
  deepMerge
};
