/**
 * Session Routes
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const express = require('express');
const router = express.Router();

const { verifySession, getCsrfToken } = require('../controllers/sessionController');
const { validate, schemas } = require('../middleware/validation');
const { strictRateLimiter } = require('../middleware/rateLimiter');

// ══════════════════════════════════════════════════════════════
// SESSION ENDPOINTS
// ══════════════════════════════════════════════════════════════

/**
 * POST /api/verify-session
 * Verify a stored session token
 */
router.post('/verify-session',
  strictRateLimiter,
  validate(schemas.sessionVerify),
  verifySession
);

/**
 * GET /api/csrf-token
 * Get a fresh CSRF token
 */
router.get('/csrf-token', getCsrfToken);

module.exports = router;
