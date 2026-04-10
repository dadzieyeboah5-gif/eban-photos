/**
 * Session Controller
 * ═══════════════════════════════════════════════════════════════
 * Handles JWT session verification for premium access
 */

'use strict';

const { verifyAccessToken } = require('../middleware/auth');

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Verify Session
// ══════════════════════════════════════════════════════════════

/**
 * Verify a stored session token
 * POST /api/verify-session
 */
async function verifySession(req, res, next) {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.json({
        valid: false,
        reason: 'No token provided'
      });
    }
    
    const decoded = verifyAccessToken(token);
    
    if (!decoded) {
      return res.json({
        valid: false,
        reason: 'Invalid or expired token'
      });
    }
    
    // Token is valid
    res.json({
      valid: true,
      product: decoded.product,
      email: decoded.email,
      purchaseDate: decoded.purchaseDate,
      expiresAt: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null
    });
    
  } catch (err) {
    // Don't expose internal errors for session verification
    res.json({
      valid: false,
      reason: 'Verification failed'
    });
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Get CSRF Token
// ══════════════════════════════════════════════════════════════

/**
 * Get a fresh CSRF token
 * GET /api/csrf-token
 */
async function getCsrfToken(req, res) {
  const { generateToken } = require('../middleware/csrf');
  
  res.json({
    csrfToken: generateToken()
  });
}

module.exports = {
  verifySession,
  getCsrfToken
};
