/**
 * Payment Routes
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const express = require('express');
const router = express.Router();

const {
  initializePayment,
  verifyPayment,
  handleWebhook,
  getPaymentStatus
} = require('../controllers/paymentController');

const { validate, schemas } = require('../middleware/validation');
const { paymentRateLimiter } = require('../middleware/rateLimiter');

// ══════════════════════════════════════════════════════════════
// PAYMENT ENDPOINTS
// ══════════════════════════════════════════════════════════════

/**
 * POST /api/pay
 * Initialize a Paystack transaction
 */
router.post('/pay',
  paymentRateLimiter,
  validate(schemas.paymentInit),
  initializePayment
);

/**
 * POST /api/verify-payment
 * Verify a completed Paystack transaction
 */
router.post('/verify-payment',
  paymentRateLimiter,
  validate(schemas.paymentVerify),
  verifyPayment
);

/**
 * POST /api/webhook/paystack
 * Paystack webhook endpoint
 * NOTE: Use raw body parser for signature verification
 */
router.post('/webhook/paystack',
  express.raw({ type: 'application/json' }),
  (req, res, next) => {
    // Parse raw body to JSON for webhook handler
    try {
      req.body = JSON.parse(req.body.toString());
      next();
    } catch (err) {
      res.status(400).send('Invalid JSON');
    }
  },
  handleWebhook
);

/**
 * GET /api/payment-status/:reference
 * Check payment status (for polling)
 */
router.get('/payment-status/:reference', getPaymentStatus);

module.exports = router;
