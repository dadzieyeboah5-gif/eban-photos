/**
 * Booking Routes
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const express = require('express');
const router = express.Router();

const { bookSession } = require('../controllers/bookingController');
const { validate, schemas } = require('../middleware/validation');
const { bookingRateLimiter } = require('../middleware/rateLimiter');

// ══════════════════════════════════════════════════════════════
// BOOKING ENDPOINTS
// ══════════════════════════════════════════════════════════════

/**
 * POST /api/book-session
 * Submit a booking request
 */
router.post('/book-session',
  bookingRateLimiter,
  validate(schemas.booking),
  bookSession
);

module.exports = router;
