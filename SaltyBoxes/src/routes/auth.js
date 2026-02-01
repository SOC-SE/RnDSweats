/**
 * Authentication Routes
 *
 * Handles user login, logout, session status, and password changes.
 *
 * @module routes/auth
 */

const express = require('express');
const router = express.Router();
const {
  validateCredentials,
  changePassword,
  hasUsers,
  createOrUpdateUser,
  sanitizeUsername,
  validatePasswordStrength
} = require('../lib/auth');
const logger = require('../lib/logger');
const { requireAuth, getClientIP } = require('../middleware/auth');

/**
 * POST /api/auth/login
 * Authenticate user and create session
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const clientIP = getClientIP(req);

  // Validate input
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Username and password are required'
    });
  }

  const sanitizedUsername = sanitizeUsername(username);
  if (!sanitizedUsername) {
    return res.status(400).json({
      success: false,
      error: 'Invalid username format'
    });
  }

  try {
    const result = await validateCredentials(sanitizedUsername, password);

    if (!result.valid) {
      logger.audit({
        user: sanitizedUsername,
        ip: clientIP,
        action: 'auth.login',
        result: 'failure',
        details: { reason: 'invalid_credentials' }
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    // Create session
    req.session.user = result.user;
    req.session.lastActivity = Date.now();
    req.session.loginTime = Date.now();

    logger.audit({
      user: sanitizedUsername,
      ip: clientIP,
      action: 'auth.login',
      result: 'success'
    });

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        username: result.user.username,
        role: result.user.role
      }
    });
  } catch (error) {
    logger.error('Login error', error);
    res.status(500).json({
      success: false,
      error: 'Authentication error'
    });
  }
});

/**
 * POST /api/auth/logout
 * End user session
 */
router.post('/logout', (req, res) => {
  const username = req.session?.user?.username || 'unknown';
  const clientIP = getClientIP(req);

  req.session.destroy((err) => {
    if (err) {
      logger.error('Session destroy error', err);
    }

    logger.audit({
      user: username,
      ip: clientIP,
      action: 'auth.logout',
      result: 'success'
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  });
});

/**
 * GET /api/auth/status
 * Check current authentication status
 */
router.get('/status', (req, res) => {
  const authenticated = !!(req.session && req.session.user);

  res.json({
    success: true,
    authenticated,
    user: authenticated ? {
      username: req.session.user.username,
      role: req.session.user.role
    } : null,
    sessionAge: authenticated ?
      Math.floor((Date.now() - req.session.loginTime) / 1000) : null
  });
});

/**
 * POST /api/auth/change-password
 * Change the current user's password
 */
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const username = req.session.user.username;
  const clientIP = getClientIP(req);

  // Validate input
  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      error: 'Current password and new password are required'
    });
  }

  // Validate password strength
  const strength = validatePasswordStrength(newPassword);
  if (!strength.valid) {
    return res.status(400).json({
      success: false,
      error: strength.errors.join(', ')
    });
  }

  try {
    const result = await changePassword(username, currentPassword, newPassword);

    if (!result.success) {
      logger.audit({
        user: username,
        ip: clientIP,
        action: 'auth.change_password',
        result: 'failure',
        details: { reason: result.message }
      });

      return res.status(400).json({
        success: false,
        error: result.message
      });
    }

    logger.audit({
      user: username,
      ip: clientIP,
      action: 'auth.change_password',
      result: 'success'
    });

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    logger.error('Password change error', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change password'
    });
  }
});

/**
 * POST /api/auth/setup
 * Initial admin setup (only works if no users exist)
 */
router.post('/setup', async (req, res) => {
  const { username, password } = req.body;
  const clientIP = getClientIP(req);

  // Only allow setup if no users exist
  if (hasUsers()) {
    return res.status(403).json({
      success: false,
      error: 'Setup already complete. Users already exist.'
    });
  }

  // Validate input
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Username and password are required'
    });
  }

  const sanitizedUsername = sanitizeUsername(username);
  if (!sanitizedUsername) {
    return res.status(400).json({
      success: false,
      error: 'Invalid username format'
    });
  }

  // Validate password strength
  const strength = validatePasswordStrength(password);
  if (!strength.valid) {
    return res.status(400).json({
      success: false,
      error: strength.errors.join(', ')
    });
  }

  try {
    await createOrUpdateUser(sanitizedUsername, password, 'admin');

    logger.audit({
      user: sanitizedUsername,
      ip: clientIP,
      action: 'auth.setup',
      result: 'success',
      details: { role: 'admin' }
    });

    logger.info(`Initial admin user '${sanitizedUsername}' created`);

    res.json({
      success: true,
      message: `Admin user '${sanitizedUsername}' created successfully`
    });
  } catch (error) {
    logger.error('Setup error', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create user'
    });
  }
});

/**
 * GET /api/auth/setup-required
 * Check if initial setup is required
 */
router.get('/setup-required', (req, res) => {
  res.json({
    success: true,
    setupRequired: !hasUsers()
  });
});

module.exports = router;
