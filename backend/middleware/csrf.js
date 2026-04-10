/**
 * CSRF Protection Middleware
 * ═══════════════════════════════════════════════════════════════
 * Prevents Cross-Site Request Forgery attacks
 */

'use strict';

const crypto = require('crypto');

// In-memory token store (use Redis in production for scaling)
const tokenStore = new Map();

// Token expiration time (30 minutes)
const TOKEN_EXPIRY = 30 * 60 * 1000;

// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokenStore.entries()) {
    if (now - data.createdAt > TOKEN_EXPIRY) {
      tokenStore.delete(token);
    }
  }
}, 5 * 60 * 1000); // Every 5 minutes

/**
 * Generate a new CSRF token
 */
function generateToken() {
  const token = crypto.randomBytes(32).toString('hex');
  tokenStore.set(token, {
    createdAt: Date.now()
  });
  return token;
}

/**
 * Validate a CSRF token
 */
function validateToken(token) {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
  // Validate token format (64 hex characters)
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return false;
  }
  
  const data = tokenStore.get(token);
  if (!data) {
    return false;
  }
  
  // Check if token has expired
  if (Date.now() - data.createdAt > TOKEN_EXPIRY) {
    tokenStore.delete(token);
    return false;
  }
  
  // Token is valid — consume it (one-time use)
  tokenStore.delete(token);
  return true;
}

/**
 * CSRF Protection Middleware
 * Validates CSRF token from header or body
 */
function csrfProtection(req, res, next) {
  // Skip for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Get token from header or body
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  
  if (!validateToken(token)) {
    return res.status(403).json({
      error: 'Invalid or missing CSRF token',
      code: 'CSRF_INVALID'
    });
  }
  
  next();
}

/**
 * Middleware to generate and attach CSRF token
 */
function csrfTokenGenerator(req, res, next) {
  req.csrfToken = generateToken;
  res.locals.csrfToken = generateToken();
  next();
}

module.exports = {
  csrfProtection,
  csrfTokenGenerator,
  generateToken,
  validateToken
};
