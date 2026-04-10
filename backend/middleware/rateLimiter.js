/**
 * Rate Limiting Middleware
 * ═══════════════════════════════════════════════════════════════
 * Prevents brute force attacks and API abuse
 */

'use strict';

const rateLimit = require('express-rate-limit');

// ══════════════════════════════════════════════════════════════
// General API Rate Limiter
// ══════════════════════════════════════════════════════════════
const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window per IP
  message: {
    error: 'Too many requests. Please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for health checks
  skip: (req) => req.path === '/health',
  // Custom key generator for proxy environments
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  }
});

// ══════════════════════════════════════════════════════════════
// Strict Rate Limiter — For sensitive endpoints
// ══════════════════════════════════════════════════════════════
const strictRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // 5 requests per window per IP
  message: {
    error: 'Too many attempts. Please wait before trying again.',
    retryAfter: '5 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  }
});

// ══════════════════════════════════════════════════════════════
// Payment Rate Limiter — For payment endpoints
// ══════════════════════════════════════════════════════════════
const paymentRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10, // 10 payment attempts per window
  message: {
    error: 'Too many payment attempts. Please wait before trying again.',
    retryAfter: '10 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use email if available for better tracking
    const email = req.body?.email;
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    return email ? `${ip}:${email}` : ip;
  }
});

// ══════════════════════════════════════════════════════════════
// Booking Rate Limiter — For booking form submissions
// ══════════════════════════════════════════════════════════════
const bookingRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 booking requests per hour
  message: {
    error: 'Too many booking requests. Please try again later.',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = {
  rateLimiter,
  strictRateLimiter,
  paymentRateLimiter,
  bookingRateLimiter
};
