/**
 * Input Validation Middleware
 * ═══════════════════════════════════════════════════════════════
 * Joi-based validation for all API inputs
 */

'use strict';

const Joi = require('joi');

// ══════════════════════════════════════════════════════════════
// VALIDATION SCHEMAS
// ══════════════════════════════════════════════════════════════

/**
 * Payment initialization schema
 */
const paymentInitSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .max(200)
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  
  name: Joi.string()
    .min(2)
    .max(100)
    .pattern(/^[\p{L}\s'\-\.]+$/u)
    .required()
    .messages({
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name must not exceed 100 characters',
      'string.pattern.base': 'Name contains invalid characters',
      'any.required': 'Name is required'
    }),
  
  paymentMethod: Joi.string()
    .valid('momo', 'card')
    .default('momo')
    .messages({
      'any.only': 'Invalid payment method'
    }),
  
  product: Joi.string()
    .valid('premium_archive')
    .required()
    .messages({
      'any.only': 'Invalid product',
      'any.required': 'Product is required'
    })
});

/**
 * Payment verification schema
 */
const paymentVerifySchema = Joi.object({
  reference: Joi.string()
    .pattern(/^[a-zA-Z0-9_\-]{8,128}$/)
    .required()
    .messages({
      'string.pattern.base': 'Invalid payment reference format',
      'any.required': 'Payment reference is required'
    }),
  
  product: Joi.string()
    .valid('premium_archive')
    .required()
    .messages({
      'any.only': 'Invalid product',
      'any.required': 'Product is required'
    })
});

/**
 * Session verification schema
 */
const sessionVerifySchema = Joi.object({
  token: Joi.string()
    .pattern(/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Invalid token format',
      'any.required': 'Token is required'
    })
});

/**
 * Booking form schema
 */
const bookingSchema = Joi.object({
  first_name: Joi.string()
    .min(1)
    .max(80)
    .pattern(/^[\p{L}\s'\-\.]+$/u)
    .required()
    .messages({
      'string.min': 'First name is required',
      'string.max': 'First name must not exceed 80 characters',
      'any.required': 'First name is required'
    }),
  
  last_name: Joi.string()
    .min(1)
    .max(80)
    .pattern(/^[\p{L}\s'\-\.]+$/u)
    .required()
    .messages({
      'string.min': 'Last name is required',
      'string.max': 'Last name must not exceed 80 characters',
      'any.required': 'Last name is required'
    }),
  
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .max(200)
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
  
  country_code: Joi.string()
    .pattern(/^\+\d{1,4}$/)
    .default('+233'),
  
  phone: Joi.string()
    .pattern(/^[0-9]{7,15}$/)
    .allow('')
    .optional()
    .messages({
      'string.pattern.base': 'Phone number must be 7-15 digits'
    }),
  
  service: Joi.string()
    .valid('portrait', 'editorial', 'ceremony', 'lifestyle', 'other')
    .required()
    .messages({
      'any.only': 'Please select a valid service type',
      'any.required': 'Service type is required'
    }),
  
  preferred_date: Joi.string()
    .pattern(/^\d{4}-\d{2}-\d{2}$/)
    .allow('')
    .optional()
    .messages({
      'string.pattern.base': 'Invalid date format (use YYYY-MM-DD)'
    }),
  
  message: Joi.string()
    .min(1)
    .max(2000)
    .required()
    .messages({
      'string.min': 'Please share a brief message about your vision',
      'string.max': 'Message must not exceed 2000 characters',
      'any.required': 'Message is required'
    }),
  
  // Honeypot fields - should be empty
  _gotcha: Joi.string().max(0).allow('').optional(),
  website: Joi.string().max(0).allow('').optional(),
  
  // CSRF token
  _csrf: Joi.string().optional(),
  _subject: Joi.string().optional()
});

/**
 * Premium image filename schema
 */
const imageFilenameSchema = Joi.object({
  filename: Joi.string()
    .pattern(/^[a-zA-Z0-9_\-]+\.(jpg|jpeg|png|webp)$/i)
    .max(100)
    .required()
    .messages({
      'string.pattern.base': 'Invalid filename format',
      'any.required': 'Filename is required'
    })
});

// ══════════════════════════════════════════════════════════════
// VALIDATION MIDDLEWARE FACTORY
// ══════════════════════════════════════════════════════════════

/**
 * Create validation middleware for a schema
 * @param {Joi.Schema} schema - Joi validation schema
 * @param {string} property - Request property to validate ('body', 'params', 'query')
 */
function validate(schema, property = 'body') {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false, // Return all errors
      stripUnknown: true, // Remove unknown fields
      convert: true // Type coercion
    });
    
    if (error) {
      const details = error.details.map(d => ({
        field: d.path.join('.'),
        message: d.message
      }));
      
      const validationError = new Error('Validation failed');
      validationError.name = 'ValidationError';
      validationError.details = details;
      
      return next(validationError);
    }
    
    // Replace request data with validated/sanitized data
    req[property] = value;
    next();
  };
}

// ══════════════════════════════════════════════════════════════
// SANITIZATION HELPERS
// ══════════════════════════════════════════════════════════════

/**
 * Sanitize string input (prevent XSS)
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#x60;')
    .replace(/=/g, '&#x3D;');
}

/**
 * Sanitize object recursively
 */
function sanitizeObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return typeof obj === 'string' ? sanitizeString(obj) : obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[sanitizeString(key)] = sanitizeObject(value);
  }
  return sanitized;
}

module.exports = {
  validate,
  sanitizeString,
  sanitizeObject,
  schemas: {
    paymentInit: paymentInitSchema,
    paymentVerify: paymentVerifySchema,
    sessionVerify: sessionVerifySchema,
    booking: bookingSchema,
    imageFilename: imageFilenameSchema
  }
};
