/**
 * JWT Authentication Middleware
 * ═══════════════════════════════════════════════════════════════
 * Handles JWT token generation and verification for premium access
 */

'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '365d'; // 1 year for "lifetime access"
const JWT_ISSUER = 'eban-photos';
const JWT_AUDIENCE = 'premium-content';

/**
 * Generate access token for premium content
 * @param {Object} payload - Token payload
 * @returns {string} JWT token
 */
function generateAccessToken(payload) {
  const tokenData = {
    ...payload,
    type: 'premium_access',
    createdAt: Date.now()
  };
  
  return jwt.sign(tokenData, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    subject: payload.email || payload.reference
  });
}

/**
 * Verify and decode access token
 * @param {string} token - JWT token
 * @returns {Object|null} Decoded payload or null if invalid
 */
function verifyAccessToken(token) {
  try {
    if (!token || typeof token !== 'string') {
      return null;
    }
    
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
    
    // Additional validation
    if (decoded.type !== 'premium_access') {
      return null;
    }
    
    return decoded;
  } catch (err) {
    // Token is invalid or expired
    return null;
  }
}

/**
 * Extract token from Authorization header or body
 * @param {Object} req - Express request
 * @returns {string|null} Token or null
 */
function extractToken(req) {
  // Check Authorization header (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  
  // Check body
  if (req.body && req.body.token) {
    return req.body.token;
  }
  
  // Check query string (for direct image access)
  if (req.query && req.query.token) {
    return req.query.token;
  }
  
  return null;
}

/**
 * Middleware: Require valid premium access token
 */
function requirePremiumAccess(req, res, next) {
  const token = extractToken(req);
  
  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Premium access token required',
      code: 'TOKEN_REQUIRED'
    });
  }
  
  const decoded = verifyAccessToken(token);
  
  if (!decoded) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired access token',
      code: 'TOKEN_INVALID'
    });
  }
  
  // Attach decoded token to request
  req.premiumAccess = decoded;
  next();
}

/**
 * Middleware: Optional premium access (doesn't fail if no token)
 */
function optionalPremiumAccess(req, res, next) {
  const token = extractToken(req);
  
  if (token) {
    const decoded = verifyAccessToken(token);
    if (decoded) {
      req.premiumAccess = decoded;
    }
  }
  
  next();
}

module.exports = {
  generateAccessToken,
  verifyAccessToken,
  extractToken,
  requirePremiumAccess,
  optionalPremiumAccess
};
