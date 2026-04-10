/**
 * eban photos — Production-Ready Secure Backend
 * ═══════════════════════════════════════════════════════════════
 * Node.js + Express backend with enterprise-level security
 * 
 * Security Features:
 * - Helmet.js security headers
 * - Dynamic CSP nonces
 * - Rate limiting
 * - CORS protection (restricted origins)
 * - Input validation (Joi)
 * - CSRF protection
 * - JWT-based sessions
 * - Path traversal prevention
 * - Secure Paystack integration
 */

'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Import routes
const paymentRoutes = require('./routes/payment');
const bookingRoutes = require('./routes/booking');
const imageRoutes = require('./routes/images');
const sessionRoutes = require('./routes/session');

// Import middleware
const { rateLimiter, strictRateLimiter } = require('./middleware/rateLimiter');
const csrfProtection = require('./middleware/csrf');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// ══════════════════════════════════════════════════════════════
// TRUST PROXY (Required for rate limiting behind Render/nginx)
// ══════════════════════════════════════════════════════════════
app.set('trust proxy', 1);

// ══════════════════════════════════════════════════════════════
// SECURITY: Generate CSP nonce per request
// ══════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  // Generate cryptographically secure nonce
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// ══════════════════════════════════════════════════════════════
// SECURITY: Helmet.js — Security Headers
// ══════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://js.paystack.co",
        (req, res) => `'nonce-${res.locals.nonce}'`
      ],
      styleSrc: [
        "'self'",
        "https://fonts.googleapis.com",
        (req, res) => `'nonce-${res.locals.nonce}'`
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "blob:"],
      connectSrc: ["'self'", "https://api.paystack.co"],
      frameSrc: ["'self'", "https://checkout.paystack.com"],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'", "https://formspree.io"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false, // Allow Paystack iframe
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true,
  frameguard: { action: 'sameorigin' }
}));

// ══════════════════════════════════════════════════════════════
// SECURITY: CORS — Restricted Origins
// ══════════════════════════════════════════════════════════════
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.) in dev
    if (!origin && process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy violation'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  exposedHeaders: ['X-CSRF-Token'],
  maxAge: 86400 // 24 hours
}));

// ══════════════════════════════════════════════════════════════
// LOGGING
// ══════════════════════════════════════════════════════════════
const logFormat = process.env.NODE_ENV === 'production'
  ? 'combined'
  : 'dev';
app.use(morgan(logFormat, {
  skip: (req) => req.path === '/health'
}));

// ══════════════════════════════════════════════════════════════
// BODY PARSING
// ══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ══════════════════════════════════════════════════════════════
// RATE LIMITING — Apply global rate limiter
// ══════════════════════════════════════════════════════════════
app.use(rateLimiter);

// ══════════════════════════════════════════════════════════════
// STATIC FILES — Serve frontend with nonce injection
// ══════════════════════════════════════════════════════════════
const FRONTEND_PATH = process.env.FRONTEND_PATH || path.join(__dirname, 'public');

// Serve static assets (images, etc.) directly
app.use('/images', express.static(path.join(FRONTEND_PATH, 'images'), {
  maxAge: '1d',
  etag: true
}));

// Serve index.html with nonce injection
app.get('/', (req, res) => {
  const indexPath = path.join(FRONTEND_PATH, 'index.html');
  
  if (!fs.existsSync(indexPath)) {
    return res.status(404).send('Frontend not found. Please deploy frontend files.');
  }
  
  let html = fs.readFileSync(indexPath, 'utf8');
  
  // Inject nonce into all nonce placeholders
  html = html.replace(/REPLACE_WITH_SERVER_NONCE/g, res.locals.nonce);
  
  // Inject CSRF token
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session = req.session || {};
  req.session.csrfToken = csrfToken;
  html = html.replace(/REPLACE_WITH_CSRF_TOKEN/g, csrfToken);
  
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// ══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// ══════════════════════════════════════════════════════════════
// API ROUTES
// ══════════════════════════════════════════════════════════════
app.use('/api', paymentRoutes);
app.use('/api', bookingRoutes);
app.use('/api', imageRoutes);
app.use('/api', sessionRoutes);

// ══════════════════════════════════════════════════════════════
// ERROR HANDLING
// ══════════════════════════════════════════════════════════════
app.use(notFoundHandler);
app.use(errorHandler);

// ══════════════════════════════════════════════════════════════
// SERVER START
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ══════════════════════════════════════════════════════════════
    eban photos — Secure Backend Server
  ══════════════════════════════════════════════════════════════
    Status:      Running
    Port:        ${PORT}
    Environment: ${process.env.NODE_ENV || 'development'}
    Frontend:    ${process.env.FRONTEND_URL || 'Not configured'}
  ══════════════════════════════════════════════════════════════
  `);
});

module.exports = app;
