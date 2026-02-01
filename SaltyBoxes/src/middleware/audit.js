/**
 * Audit Logging Middleware
 *
 * Logs administrative actions to the audit trail.
 *
 * @module middleware/audit
 */

const logger = require('../lib/logger');
const { getClientIP } = require('./auth');

/**
 * Create audit logging middleware for specific actions
 * @param {string} actionName - Name of the action being performed
 * @returns {Function} Middleware function
 */
function auditAction(actionName) {
  return (req, res, next) => {
    const startTime = Date.now();

    // Mark request as having explicit audit so auditAllMutations skips it
    req._auditHandled = true;

    // Capture the original json method to intercept response
    const originalJson = res.json.bind(res);

    res.json = (data) => {
      const duration = Date.now() - startTime;
      const success = data.success !== false && res.statusCode < 400;

      // Extract relevant details for audit
      const details = extractAuditDetails(req);

      logger.audit({
        user: req.session?.user?.username || 'anonymous',
        ip: getClientIP(req),
        action: actionName,
        targets: extractTargets(req),
        details,
        result: success ? 'success' : 'failure',
        duration_ms: duration
      });

      return originalJson(data);
    };

    next();
  };
}

/**
 * Extract targets from request body
 * @param {Object} req - Express request
 * @returns {string|string[]|undefined} Target(s)
 */
function extractTargets(req) {
  const body = req.body || {};

  // Common target field names
  if (body.targets) return body.targets;
  if (body.target) return body.target;
  if (body.tgt) return body.tgt;
  if (body.minions) return body.minions;
  if (body.minion) return body.minion;

  // For URL params
  if (req.params?.target) return req.params.target;
  if (req.params?.minion) return req.params.minion;

  return undefined;
}

/**
 * Extract audit-relevant details from request
 * Automatically sanitizes sensitive fields
 * @param {Object} req - Express request
 * @returns {Object} Sanitized details
 */
function extractAuditDetails(req) {
  const body = req.body || {};
  const details = {};

  // Include common fields
  if (body.command) details.command = truncate(body.command, 200);
  if (body.script) details.script = body.script;
  if (body.state) details.state = body.state;
  if (body.service) details.service = body.service;
  if (body.action) details.action = body.action;
  if (body.shell) details.shell = body.shell;
  if (body.timeout) details.timeout = body.timeout;
  if (body.username) details.username = body.username;

  // Note: password fields are excluded by design

  return Object.keys(details).length > 0 ? details : undefined;
}

/**
 * Truncate string to max length
 * @param {string} str - String to truncate
 * @param {number} maxLen - Maximum length
 * @returns {string} Truncated string
 */
function truncate(str, maxLen) {
  if (typeof str !== 'string') return str;
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}

/**
 * Audit all POST/PUT/DELETE requests automatically
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
function auditAllMutations(req, res, next) {
  // Only audit mutation requests
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    return next();
  }

  // Skip if already handled by a route-specific auditAction() middleware
  if (req._auditHandled) {
    return next();
  }

  // Skip certain paths that are too noisy or not security-relevant
  const skipPaths = ['/api/health', '/api/auth/status'];
  if (skipPaths.some(p => req.path.startsWith(p))) {
    return next();
  }

  const startTime = Date.now();
  const originalJson = res.json.bind(res);

  res.json = (data) => {
    const duration = Date.now() - startTime;
    const success = data.success !== false && res.statusCode < 400;

    // Build action name from method and path
    // Clean up path: remove /api/ prefix, leading/trailing slashes, then convert / to .
    const cleanPath = req.path
      .replace(/^\/api\//, '')  // Remove /api/ prefix
      .replace(/^\/+|\/+$/g, '') // Remove leading/trailing slashes
      .replace(/\//g, '.');     // Convert remaining slashes to dots
    const action = `${req.method.toLowerCase()}.${cleanPath || 'root'}`;

    logger.audit({
      user: req.session?.user?.username || 'anonymous',
      ip: getClientIP(req),
      action,
      targets: extractTargets(req),
      details: extractAuditDetails(req),
      result: success ? 'success' : 'failure',
      duration_ms: duration
    });

    return originalJson(data);
  };

  next();
}

module.exports = {
  auditAction,
  auditAllMutations,
  extractTargets,
  extractAuditDetails
};
