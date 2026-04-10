/**
 * Error Handling Middleware
 * ═══════════════════════════════════════════════════════════════
 * Centralized error handling with proper logging
 */

'use strict';

/**
 * 404 Not Found Handler
 */
function notFoundHandler(req, res, next) {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`,
    code: 'NOT_FOUND'
  });
}

/**
 * Global Error Handler
 */
function errorHandler(err, req, res, next) {
  // Log error (in production, use a proper logging service)
  console.error('═══════════════════════════════════════════════════════════');
  console.error(`[ERROR] ${new Date().toISOString()}`);
  console.error(`Path: ${req.method} ${req.path}`);
  console.error(`Message: ${err.message}`);
  if (process.env.NODE_ENV !== 'production') {
    console.error(`Stack: ${err.stack}`);
  }
  console.error('═══════════════════════════════════════════════════════════');
  
  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      message: err.message,
      details: err.details || undefined,
      code: 'VALIDATION_ERROR'
    });
  }
  
  if (err.name === 'UnauthorizedError' || err.code === 'UNAUTHORIZED') {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
      code: 'UNAUTHORIZED'
    });
  }
  
  if (err.code === 'CORS_ERROR') {
    return res.status(403).json({
      error: 'CORS Error',
      message: 'Origin not allowed',
      code: 'CORS_ERROR'
    });
  }
  
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Payload Too Large',
      message: 'Request body exceeds size limit',
      code: 'PAYLOAD_TOO_LARGE'
    });
  }
  
  if (err.code === 'PAYSTACK_ERROR') {
    return res.status(502).json({
      error: 'Payment Gateway Error',
      message: 'Unable to process payment. Please try again.',
      code: 'PAYSTACK_ERROR'
    });
  }
  
  // Default to 500 Internal Server Error
  const statusCode = err.statusCode || err.status || 500;
  
  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal Server Error' : err.name || 'Error',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : err.message,
    code: err.code || 'INTERNAL_ERROR'
  });
}

module.exports = {
  errorHandler,
  notFoundHandler
};
