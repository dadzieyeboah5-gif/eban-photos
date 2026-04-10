/**
 * Image Controller
 * ═══════════════════════════════════════════════════════════════
 * Secure premium image access with path traversal prevention
 * 
 * SECURITY:
 * - Path traversal prevention
 * - JWT token validation
 * - Signed URL alternative
 * - Rate limiting at route level
 */

'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ══════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════

const PREMIUM_IMAGES_PATH = process.env.PREMIUM_IMAGES_PATH 
  || path.join(__dirname, '..', 'premium-images');

const SIGNED_URL_SECRET = process.env.SIGNED_URL_SECRET 
  || crypto.randomBytes(32).toString('hex');

const SIGNED_URL_EXPIRY = 60 * 60 * 1000; // 1 hour

// Allowed image extensions
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp'];

// MIME types
const MIME_TYPES = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp'
};

// ══════════════════════════════════════════════════════════════
// HELPER: Validate and sanitize filename
// ══════════════════════════════════════════════════════════════

/**
 * Validate filename to prevent path traversal
 * @param {string} filename - User-provided filename
 * @returns {Object} { valid: boolean, sanitized: string, error?: string }
 */
function validateFilename(filename) {
  if (!filename || typeof filename !== 'string') {
    return { valid: false, error: 'Filename required' };
  }
  
  // Remove any path components
  const basename = path.basename(filename);
  
  // Check for path traversal attempts
  if (filename !== basename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    console.warn(`⚠ Path traversal attempt detected: ${filename}`);
    return { valid: false, error: 'Invalid filename' };
  }
  
  // Check length
  if (basename.length > 100) {
    return { valid: false, error: 'Filename too long' };
  }
  
  // Validate characters (alphanumeric, underscore, hyphen, dot)
  if (!/^[a-zA-Z0-9_\-]+\.[a-zA-Z]+$/.test(basename)) {
    return { valid: false, error: 'Invalid filename characters' };
  }
  
  // Check extension
  const ext = path.extname(basename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return { valid: false, error: 'Invalid file type' };
  }
  
  return { valid: true, sanitized: basename };
}

/**
 * Resolve absolute path and verify it's within allowed directory
 * @param {string} filename - Validated filename
 * @returns {Object} { valid: boolean, absolutePath?: string, error?: string }
 */
function resolveSafePath(filename) {
  const absolutePath = path.resolve(PREMIUM_IMAGES_PATH, filename);
  const normalizedBase = path.resolve(PREMIUM_IMAGES_PATH);
  
  // Ensure the resolved path is within the premium images directory
  if (!absolutePath.startsWith(normalizedBase + path.sep)) {
    console.error(`⚠ Path escape attempt: ${absolutePath} not in ${normalizedBase}`);
    return { valid: false, error: 'Access denied' };
  }
  
  return { valid: true, absolutePath };
}

// ══════════════════════════════════════════════════════════════
// SIGNED URL HELPERS
// ══════════════════════════════════════════════════════════════

/**
 * Generate a signed URL for premium image access
 * @param {string} filename - Image filename
 * @param {number} expiresIn - Expiry time in milliseconds
 * @returns {Object} { url: string, expires: number }
 */
function generateSignedUrl(filename, expiresIn = SIGNED_URL_EXPIRY) {
  const expires = Date.now() + expiresIn;
  const data = `${filename}:${expires}`;
  
  const signature = crypto
    .createHmac('sha256', SIGNED_URL_SECRET)
    .update(data)
    .digest('hex');
  
  return {
    url: `/api/premium-image/${encodeURIComponent(filename)}?expires=${expires}&sig=${signature}`,
    expires
  };
}

/**
 * Verify signed URL parameters
 * @param {string} filename - Image filename
 * @param {number} expires - Expiry timestamp
 * @param {string} signature - URL signature
 * @returns {boolean} Valid or not
 */
function verifySignedUrl(filename, expires, signature) {
  // Check expiry
  if (Date.now() > parseInt(expires)) {
    return false;
  }
  
  // Verify signature
  const data = `${filename}:${expires}`;
  const expectedSig = crypto
    .createHmac('sha256', SIGNED_URL_SECRET)
    .update(data)
    .digest('hex');
  
  // Timing-safe comparison
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSig, 'hex')
    );
  } catch {
    return false;
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Get Premium Image
// ══════════════════════════════════════════════════════════════

/**
 * Serve a premium image (requires valid JWT or signed URL)
 * GET /api/premium-image/:filename
 */
async function getPremiumImage(req, res, next) {
  try {
    const { filename } = req.params;
    const { expires, sig } = req.query;
    
    // Validate filename
    const filenameValidation = validateFilename(filename);
    if (!filenameValidation.valid) {
      return res.status(400).json({
        error: filenameValidation.error,
        code: 'INVALID_FILENAME'
      });
    }
    
    const sanitizedFilename = filenameValidation.sanitized;
    
    // Check authorization (either JWT token or signed URL)
    const hasJWT = req.premiumAccess; // Set by requirePremiumAccess middleware
    const hasSignedUrl = expires && sig && verifySignedUrl(sanitizedFilename, expires, sig);
    
    if (!hasJWT && !hasSignedUrl) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Valid access token or signed URL required',
        code: 'UNAUTHORIZED'
      });
    }
    
    // Resolve safe path
    const pathValidation = resolveSafePath(sanitizedFilename);
    if (!pathValidation.valid) {
      return res.status(403).json({
        error: pathValidation.error,
        code: 'ACCESS_DENIED'
      });
    }
    
    const absolutePath = pathValidation.absolutePath;
    
    // Check file exists
    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({
        error: 'Image not found',
        code: 'NOT_FOUND'
      });
    }
    
    // Get file stats
    const stats = fs.statSync(absolutePath);
    const ext = path.extname(sanitizedFilename).toLowerCase();
    const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
    
    // Set headers
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Cache-Control', 'private, max-age=86400'); // 1 day, private cache
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Stream the file
    const readStream = fs.createReadStream(absolutePath);
    readStream.pipe(res);
    
    readStream.on('error', (err) => {
      console.error('File stream error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to read image' });
      }
    });
    
  } catch (err) {
    next(err);
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Generate Signed URLs for Album
// ══════════════════════════════════════════════════════════════

/**
 * Generate signed URLs for all premium images
 * GET /api/premium-album
 * Requires valid JWT
 */
async function getPremiumAlbum(req, res, next) {
  try {
    // Ensure premium images directory exists
    if (!fs.existsSync(PREMIUM_IMAGES_PATH)) {
      return res.json({
        images: [],
        message: 'Premium images directory not configured'
      });
    }
    
    // Read directory
    const files = fs.readdirSync(PREMIUM_IMAGES_PATH);
    
    // Filter and generate signed URLs
    const images = files
      .filter(file => {
        const ext = path.extname(file).toLowerCase();
        return ALLOWED_EXTENSIONS.includes(ext);
      })
      .map(filename => {
        const signed = generateSignedUrl(filename);
        return {
          filename,
          url: signed.url,
          expires: signed.expires
        };
      });
    
    res.json({
      images,
      count: images.length,
      expiresIn: SIGNED_URL_EXPIRY
    });
    
  } catch (err) {
    next(err);
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: List Premium Images (Admin)
// ══════════════════════════════════════════════════════════════

/**
 * List all premium images (for debugging/admin)
 * Requires ADMIN_KEY in production
 */
async function listPremiumImages(req, res) {
  // In production, require admin key
  if (process.env.NODE_ENV === 'production') {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
      return res.status(403).json({ error: 'Admin access required' });
    }
  }
  
  if (!fs.existsSync(PREMIUM_IMAGES_PATH)) {
    return res.json({
      path: PREMIUM_IMAGES_PATH,
      exists: false,
      images: []
    });
  }
  
  const files = fs.readdirSync(PREMIUM_IMAGES_PATH);
  const images = files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    return ALLOWED_EXTENSIONS.includes(ext);
  });
  
  res.json({
    path: PREMIUM_IMAGES_PATH,
    exists: true,
    count: images.length,
    images
  });
}

module.exports = {
  getPremiumImage,
  getPremiumAlbum,
  listPremiumImages,
  generateSignedUrl,
  verifySignedUrl,
  validateFilename
};
