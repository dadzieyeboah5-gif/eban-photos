/**
 * Payment Controller
 * ═══════════════════════════════════════════════════════════════
 * Secure Paystack payment handling
 * 
 * SECURITY:
 * - Secret key stored server-side only
 * - Payment verification via Paystack API
 * - Signed JWT access tokens for premium content
 */

'use strict';

const https = require('https');
const crypto = require('crypto');
const { generateAccessToken } = require('../middleware/auth');

// ══════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY;

// Product pricing (in kobo/pesewas)
const PRODUCTS = {
  premium_archive: {
    name: 'The Intimate Archive — Premium Collection',
    amount: 1500, // 15 GHS in pesewas
    currency: 'GHS'
  }
};

// In-memory storage for verified payments (use database in production)
const verifiedPayments = new Map();

// ══════════════════════════════════════════════════════════════
// HELPER: Make Paystack API request
// ══════════════════════════════════════════════════════════════

function paystackRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: path,
      method: method,
      headers: {
        'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
      }
    };
    
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed });
        } catch (err) {
          reject(new Error('Invalid JSON response from Paystack'));
        }
      });
    });
    
    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('Paystack request timeout'));
    });
    
    if (data) {
      req.write(JSON.stringify(data));
    }
    
    req.end();
  });
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Initialize Payment
// ══════════════════════════════════════════════════════════════

/**
 * Initialize a Paystack transaction
 * POST /api/pay
 */
async function initializePayment(req, res, next) {
  try {
    const { email, name, paymentMethod, product } = req.body;
    
    // Validate product
    const productData = PRODUCTS[product];
    if (!productData) {
      return res.status(400).json({
        error: 'Invalid product',
        code: 'INVALID_PRODUCT'
      });
    }
    
    // Check if already purchased (by email)
    const existingPurchase = Array.from(verifiedPayments.values())
      .find(p => p.email.toLowerCase() === email.toLowerCase() && p.product === product);
    
    if (existingPurchase) {
      // Generate new token for existing purchase
      const accessToken = generateAccessToken({
        email: email,
        product: product,
        reference: existingPurchase.reference,
        purchaseDate: existingPurchase.paidAt
      });
      
      return res.json({
        success: true,
        alreadyPurchased: true,
        accessToken: accessToken,
        message: 'You already have access to this content'
      });
    }
    
    // Generate unique reference
    const reference = `eban_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    
    // Determine Paystack channels based on payment method
    const channels = paymentMethod === 'card' 
      ? ['card'] 
      : ['mobile_money'];
    
    // Initialize transaction with Paystack
    const response = await paystackRequest('POST', '/transaction/initialize', {
      email: email,
      amount: productData.amount,
      currency: productData.currency,
      reference: reference,
      channels: channels,
      metadata: {
        custom_fields: [
          {
            display_name: 'Customer Name',
            variable_name: 'customer_name',
            value: name
          },
          {
            display_name: 'Product',
            variable_name: 'product',
            value: productData.name
          },
          {
            display_name: 'Product ID',
            variable_name: 'product_id',
            value: product
          }
        ]
      },
      callback_url: `${process.env.FRONTEND_URL || ''}#payment-callback`
    });
    
    if (response.status !== 200 || !response.data.status) {
      console.error('Paystack init error:', response.data);
      const error = new Error('Failed to initialize payment');
      error.code = 'PAYSTACK_ERROR';
      throw error;
    }
    
    res.json({
      success: true,
      reference: reference,
      authorizationUrl: response.data.data.authorization_url,
      accessCode: response.data.data.access_code,
      publicKey: PAYSTACK_PUBLIC_KEY
    });
    
  } catch (err) {
    next(err);
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Verify Payment
// ══════════════════════════════════════════════════════════════

/**
 * Verify a Paystack transaction
 * POST /api/verify-payment
 */
async function verifyPayment(req, res, next) {
  try {
    const { reference, product } = req.body;
    
    // Validate product
    const productData = PRODUCTS[product];
    if (!productData) {
      return res.status(400).json({
        verified: false,
        error: 'Invalid product',
        code: 'INVALID_PRODUCT'
      });
    }
    
    // Check if already verified
    if (verifiedPayments.has(reference)) {
      const existingPayment = verifiedPayments.get(reference);
      
      // Generate new access token
      const accessToken = generateAccessToken({
        email: existingPayment.email,
        product: product,
        reference: reference,
        purchaseDate: existingPayment.paidAt
      });
      
      return res.json({
        verified: true,
        accessToken: accessToken,
        message: 'Payment already verified'
      });
    }
    
    // Verify with Paystack API
    const response = await paystackRequest('GET', `/transaction/verify/${encodeURIComponent(reference)}`);
    
    if (response.status !== 200 || !response.data.status) {
      console.error('Paystack verify error:', response.data);
      return res.status(400).json({
        verified: false,
        error: 'Payment verification failed',
        code: 'VERIFICATION_FAILED'
      });
    }
    
    const transaction = response.data.data;
    
    // Validate transaction status
    if (transaction.status !== 'success') {
      return res.status(400).json({
        verified: false,
        error: `Payment status: ${transaction.status}`,
        code: 'PAYMENT_NOT_SUCCESS'
      });
    }
    
    // Validate amount matches product price
    if (transaction.amount !== productData.amount) {
      console.error(`Amount mismatch: expected ${productData.amount}, got ${transaction.amount}`);
      return res.status(400).json({
        verified: false,
        error: 'Payment amount mismatch',
        code: 'AMOUNT_MISMATCH'
      });
    }
    
    // Validate currency
    if (transaction.currency.toUpperCase() !== productData.currency) {
      return res.status(400).json({
        verified: false,
        error: 'Currency mismatch',
        code: 'CURRENCY_MISMATCH'
      });
    }
    
    // Store verified payment
    const paymentRecord = {
      reference: reference,
      email: transaction.customer.email,
      product: product,
      amount: transaction.amount,
      currency: transaction.currency,
      paidAt: transaction.paid_at || new Date().toISOString(),
      channel: transaction.channel,
      metadata: transaction.metadata
    };
    
    verifiedPayments.set(reference, paymentRecord);
    
    // Generate access token
    const accessToken = generateAccessToken({
      email: transaction.customer.email,
      product: product,
      reference: reference,
      purchaseDate: paymentRecord.paidAt
    });
    
    console.log(`✓ Payment verified: ${reference} - ${transaction.customer.email}`);
    
    res.json({
      verified: true,
      accessToken: accessToken,
      message: 'Payment verified successfully'
    });
    
  } catch (err) {
    next(err);
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Paystack Webhook
// ══════════════════════════════════════════════════════════════

/**
 * Handle Paystack webhook events
 * POST /api/webhook/paystack
 */
async function handleWebhook(req, res) {
  try {
    // Verify webhook signature
    const hash = crypto
      .createHmac('sha512', PAYSTACK_SECRET_KEY)
      .update(JSON.stringify(req.body))
      .digest('hex');
    
    if (hash !== req.headers['x-paystack-signature']) {
      console.error('Invalid Paystack webhook signature');
      return res.status(401).send('Invalid signature');
    }
    
    const event = req.body;
    
    console.log(`Webhook received: ${event.event}`);
    
    // Handle charge.success event
    if (event.event === 'charge.success') {
      const transaction = event.data;
      
      // Extract product from metadata
      const productId = transaction.metadata?.custom_fields?.find(
        f => f.variable_name === 'product_id'
      )?.value || 'premium_archive';
      
      // Store verified payment
      const paymentRecord = {
        reference: transaction.reference,
        email: transaction.customer.email,
        product: productId,
        amount: transaction.amount,
        currency: transaction.currency,
        paidAt: transaction.paid_at || new Date().toISOString(),
        channel: transaction.channel,
        source: 'webhook'
      };
      
      verifiedPayments.set(transaction.reference, paymentRecord);
      
      console.log(`✓ Webhook: Payment confirmed for ${transaction.reference}`);
    }
    
    res.sendStatus(200);
    
  } catch (err) {
    console.error('Webhook error:', err);
    res.sendStatus(500);
  }
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Get Payment Status
// ══════════════════════════════════════════════════════════════

/**
 * Check payment status (for frontend polling)
 * GET /api/payment-status/:reference
 */
async function getPaymentStatus(req, res) {
  const { reference } = req.params;
  
  // Validate reference format
  if (!/^[a-zA-Z0-9_\-]{8,128}$/.test(reference)) {
    return res.status(400).json({
      error: 'Invalid reference format'
    });
  }
  
  // Check local cache first
  if (verifiedPayments.has(reference)) {
    return res.json({
      status: 'verified',
      verified: true
    });
  }
  
  // Not verified yet
  res.json({
    status: 'pending',
    verified: false
  });
}

module.exports = {
  initializePayment,
  verifyPayment,
  handleWebhook,
  getPaymentStatus
};
