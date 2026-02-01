/**
 * Target Resolution Utilities
 *
 * Shared logic for validating and resolving Salt minion targets.
 * Used across all route files to eliminate duplication.
 *
 * @module lib/targets
 */

/**
 * Validate and normalize target input into a consistent format
 * for Salt API calls.
 *
 * @param {string|string[]} targets - Target input (minion IDs, glob patterns)
 * @returns {{valid: boolean, targets: string[], tgt: string|string[], tgt_type: string, error?: string}}
 */
function resolveTargets(targets) {
  if (!targets) {
    return { valid: false, error: 'Targets are required' };
  }

  // Normalize to array
  const targetList = Array.isArray(targets) ? targets : [targets];

  if (targetList.length === 0) {
    return { valid: false, error: 'At least one target is required' };
  }

  // Validate each target
  for (const target of targetList) {
    if (typeof target !== 'string' || target.length === 0) {
      return { valid: false, error: 'Invalid target format' };
    }
    // Allow alphanumeric, dots, hyphens, underscores, and glob characters
    if (!/^[a-zA-Z0-9._*?[\]-]+$/.test(target)) {
      return { valid: false, error: `Invalid target: ${target}` };
    }
  }

  // Determine tgt_type and tgt format for Salt API
  let tgt_type, tgt;
  if (targetList.length === 1 && targetList[0].includes('*')) {
    tgt_type = 'glob';
    tgt = targetList[0];
  } else if (targetList.length === 1) {
    // Single target without glob - use list for consistency
    tgt_type = 'list';
    tgt = targetList;
  } else {
    tgt_type = 'list';
    tgt = targetList;
  }

  return {
    valid: true,
    targets: targetList,
    tgt,
    tgt_type
  };
}

/**
 * Quick target validation that returns 400 on failure.
 * Express middleware-style helper for route handlers.
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {string} [bodyField='targets'] - Field name in request body
 * @returns {Object|null} Resolved target info, or null if response was sent
 */
function resolveTargetsFromReq(req, res, bodyField = 'targets') {
  const targets = req.body[bodyField] || req.params[bodyField];
  const result = resolveTargets(targets);

  if (!result.valid) {
    res.status(400).json({
      success: false,
      error: result.error
    });
    return null;
  }

  return result;
}

module.exports = {
  resolveTargets,
  resolveTargetsFromReq
};
