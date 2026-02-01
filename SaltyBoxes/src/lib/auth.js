/**
 * Authentication Module
 *
 * Handles user authentication, password hashing, and session validation.
 *
 * @module lib/auth
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getAuthConfig, saveAuthConfig } = require('./config');
const logger = require('./logger');

// Bcrypt cost factor (12 is a good balance of security and speed)
const BCRYPT_ROUNDS = 12;

/**
 * Hash a password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Bcrypt hash
 */
async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Compare a password with a hash
 * @param {string} password - Plain text password
 * @param {string} hash - Bcrypt hash
 * @returns {Promise<boolean>} True if password matches
 */
async function comparePassword(password, hash) {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    logger.error('Password comparison failed', error);
    return false;
  }
}

/**
 * Validate user credentials
 * @param {string} username - Username
 * @param {string} password - Plain text password
 * @returns {Promise<{valid: boolean, user: Object|null}>} Validation result
 */
async function validateCredentials(username, password) {
  const authConfig = getAuthConfig();

  // Check if user exists
  const user = authConfig.users?.[username];
  if (!user) {
    logger.debug(`Authentication failed: user '${username}' not found`);
    return { valid: false, user: null };
  }

  // Check password
  const passwordHash = user.password_hash;
  if (!passwordHash) {
    logger.warn(`User '${username}' has no password hash configured`);
    return { valid: false, user: null };
  }

  const isValid = await comparePassword(password, passwordHash);
  if (!isValid) {
    logger.debug(`Authentication failed: invalid password for '${username}'`);
    return { valid: false, user: null };
  }

  logger.info(`User '${username}' authenticated successfully`);
  return {
    valid: true,
    user: {
      username,
      role: user.role || 'user'
    }
  };
}

/**
 * Create or update a user
 * @param {string} username - Username
 * @param {string} password - Plain text password
 * @param {string} [role='user'] - User role
 * @returns {Promise<void>}
 */
async function createOrUpdateUser(username, password, role = 'user') {
  // Validate username (alphanumeric, underscores, hyphens only)
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    throw new Error('Invalid username format');
  }

  const passwordHash = await hashPassword(password);
  const authConfig = getAuthConfig();

  if (!authConfig.users) {
    authConfig.users = {};
  }

  authConfig.users[username] = {
    password_hash: passwordHash,
    role
  };

  saveAuthConfig(authConfig);
  logger.info(`User '${username}' created/updated`);
}

/**
 * Change a user's password
 * @param {string} username - Username
 * @param {string} currentPassword - Current password (for verification)
 * @param {string} newPassword - New password
 * @returns {Promise<{success: boolean, message: string}>} Result
 */
async function changePassword(username, currentPassword, newPassword) {
  // Verify current password first
  const validation = await validateCredentials(username, currentPassword);
  if (!validation.valid) {
    return {
      success: false,
      message: 'Current password is incorrect'
    };
  }

  // Validate new password (minimum 8 characters)
  if (newPassword.length < 8) {
    return {
      success: false,
      message: 'New password must be at least 8 characters'
    };
  }

  // Update password
  const authConfig = getAuthConfig();
  authConfig.users[username].password_hash = await hashPassword(newPassword);
  saveAuthConfig(authConfig);

  logger.info(`Password changed for user '${username}'`);
  logger.audit({
    user: username,
    ip: 'local',
    action: 'auth.change_password',
    result: 'success'
  });

  return {
    success: true,
    message: 'Password changed successfully'
  };
}

/**
 * Delete a user
 * @param {string} username - Username to delete
 * @returns {boolean} True if user was deleted
 */
function deleteUser(username) {
  const authConfig = getAuthConfig();

  if (!authConfig.users?.[username]) {
    return false;
  }

  delete authConfig.users[username];
  saveAuthConfig(authConfig);

  logger.info(`User '${username}' deleted`);
  return true;
}

/**
 * List all users (without password hashes)
 * @returns {Array<{username: string, role: string}>} User list
 */
function listUsers() {
  const authConfig = getAuthConfig();
  const users = [];

  for (const [username, data] of Object.entries(authConfig.users || {})) {
    users.push({
      username,
      role: data.role || 'user'
    });
  }

  return users;
}

/**
 * Check if any users exist
 * @returns {boolean} True if at least one user exists
 */
function hasUsers() {
  const authConfig = getAuthConfig();
  return Object.keys(authConfig.users || {}).length > 0;
}

/**
 * Generate a secure random session secret
 * @param {number} [length=32] - Number of bytes
 * @returns {string} Hex-encoded random string
 */
function generateSessionSecret(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a secure random token
 * @param {number} [length=32] - Number of bytes
 * @returns {string} Hex-encoded random string
 */
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {{valid: boolean, errors: string[]}} Validation result
 */
function validatePasswordStrength(password) {
  const errors = [];

  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }

  // Optional: Add more strength requirements
  // if (!/[A-Z]/.test(password)) {
  //   errors.push('Password must contain at least one uppercase letter');
  // }
  // if (!/[a-z]/.test(password)) {
  //   errors.push('Password must contain at least one lowercase letter');
  // }
  // if (!/[0-9]/.test(password)) {
  //   errors.push('Password must contain at least one number');
  // }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Sanitize username for logging (prevent injection)
 * @param {string} username - Raw username input
 * @returns {string} Sanitized username
 */
function sanitizeUsername(username) {
  if (typeof username !== 'string') {
    return '';
  }
  // Allow only alphanumeric, underscore, hyphen
  return username.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
}

module.exports = {
  hashPassword,
  comparePassword,
  validateCredentials,
  createOrUpdateUser,
  changePassword,
  deleteUser,
  listUsers,
  hasUsers,
  generateSessionSecret,
  generateToken,
  validatePasswordStrength,
  sanitizeUsername
};
