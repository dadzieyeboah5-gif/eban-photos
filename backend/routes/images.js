/**
 * Image Routes
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const express = require('express');
const router = express.Router();

const {
  getPremiumImage,
  getPremiumAlbum,
  listPremiumImages
} = require('../controllers/imageController');

const { requirePremiumAccess, optionalPremiumAccess } = require('../middleware/auth');
const { strictRateLimiter } = require('../middleware/rateLimiter');

// ══════════════════════════════════════════════════════════════
// PREMIUM IMAGE ENDPOINTS
// ══════════════════════════════════════════════════════════════

/**
 * GET /api/premium-image/:filename
 * Serve a premium image
 * Accepts either JWT token (Bearer header) or signed URL params
 */
router.get('/premium-image/:filename',
  strictRateLimiter,
  optionalPremiumAccess, // Sets req.premiumAccess if valid token present
  getPremiumImage
);

/**
 * GET /api/premium-album
 * Get signed URLs for all premium images
 * Requires valid JWT
 */
router.get('/premium-album',
  requirePremiumAccess,
  getPremiumAlbum
);

/**
 * GET /api/admin/images
 * List all premium images (admin/debug)
 */
router.get('/admin/images', listPremiumImages);

module.exports = router;
