/**
 * Authentication Middleware
 *
 * Protects routes requiring authentication.
 *
 * @module middleware/auth
 */

const logger = require('../lib/logger');

/**
 * Require authentication middleware
 * Returns 401 if user is not authenticated
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    // Update last activity timestamp
    req.session.lastActivity = Date.now();
    return next();
  }

  logger.debug(`Unauthorized request to ${req.path}`);
  res.status(401).json({
    success: false,
    error: 'Authentication required'
  });
}

/**
 * Require admin role middleware
 * Returns 403 if user is not an admin
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  if (req.session.user.role !== 'admin') {
    logger.warn(`Non-admin user '${req.session.user.username}' attempted admin action`);
    return res.status(403).json({
      success: false,
      error: 'Admin privileges required'
    });
  }

  next();
}

/**
 * Get client IP address from request
 * Handles proxy headers
 *
 * @param {Object} req - Express request
 * @returns {string} Client IP address
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.connection?.remoteAddress ||
         req.ip ||
         'unknown';
}

/**
 * Attach user info and IP to request
 * Should be used early in middleware chain
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
function attachRequestInfo(req, res, next) {
  req.clientIP = getClientIP(req);
  req.username = req.session?.user?.username || 'anonymous';
  next();
}

/**
 * Session timeout checker middleware
 * Destroys session if inactive for too long
 *
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Function} Middleware function
 */
function sessionTimeout(timeoutMs) {
  return (req, res, next) => {
    if (req.session && req.session.user && req.session.lastActivity) {
      const now = Date.now();
      if (now - req.session.lastActivity > timeoutMs) {
        const username = req.session.user.username;
        req.session.destroy((err) => {
          if (err) {
            logger.error('Session destroy error', err);
          }
          logger.info(`Session expired for user '${username}'`);
        });
        return res.status(401).json({
          success: false,
          error: 'Session expired'
        });
      }
    }
    next();
  };
}

module.exports = {
  requireAuth,
  requireAdmin,
  getClientIP,
  attachRequestInfo,
  sessionTimeout
};
