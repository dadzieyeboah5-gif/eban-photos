/**
 * Booking Controller
 * ═══════════════════════════════════════════════════════════════
 * Handles session booking form submissions
 * 
 * Features:
 * - Input validation and sanitization
 * - Honeypot spam detection
 * - Email notifications via Nodemailer
 * - Rate limiting (applied at route level)
 */

'use strict';

const nodemailer = require('nodemailer');
const { sanitizeString } = require('../middleware/validation');

// ══════════════════════════════════════════════════════════════
// EMAIL CONFIGURATION
// ══════════════════════════════════════════════════════════════

let transporter = null;

// Initialize email transporter
function initializeMailer() {
  if (process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    
    // Verify connection
    transporter.verify((error) => {
      if (error) {
        console.error('SMTP connection error:', error);
        transporter = null;
      } else {
        console.log('✓ SMTP server connected');
      }
    });
  } else {
    console.log('⚠ SMTP not configured — email notifications disabled');
  }
}

// Initialize on module load
initializeMailer();

// ══════════════════════════════════════════════════════════════
// HELPER: Format booking email
// ══════════════════════════════════════════════════════════════

function formatBookingEmail(data) {
  const serviceLabels = {
    portrait: 'Portrait Session',
    editorial: 'Editorial / Brand',
    ceremony: 'Ceremony / Event',
    lifestyle: 'Lifestyle',
    other: 'Other'
  };
  
  const serviceName = serviceLabels[data.service] || data.service;
  const phone = data.phone ? `${data.country_code || '+233'} ${data.phone}` : 'Not provided';
  const date = data.preferred_date || 'Flexible';
  
  const textBody = `
═══════════════════════════════════════════════════════════════
  NEW SESSION REQUEST — eban photos
═══════════════════════════════════════════════════════════════

Client:        ${data.first_name} ${data.last_name}
Email:         ${data.email}
Phone:         ${phone}
Service:       ${serviceName}
Preferred Date: ${date}

───────────────────────────────────────────────────────────────
  MESSAGE
───────────────────────────────────────────────────────────────

${data.message}

───────────────────────────────────────────────────────────────
  Submitted: ${new Date().toLocaleString('en-GB', { timeZone: 'Africa/Accra' })}
═══════════════════════════════════════════════════════════════
`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #1a1e0a; color: #e8d96a; padding: 24px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 400; font-style: italic; }
    .content { padding: 24px; background: #f9f9f9; }
    .field { margin-bottom: 16px; }
    .field-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #666; margin-bottom: 4px; }
    .field-value { font-size: 16px; color: #1a1e0a; }
    .message-box { background: white; padding: 20px; border-left: 3px solid #e8d96a; margin-top: 20px; }
    .footer { text-align: center; padding: 16px; font-size: 12px; color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>New Session Request</h1>
    </div>
    <div class="content">
      <div class="field">
        <div class="field-label">Client</div>
        <div class="field-value">${sanitizeString(data.first_name)} ${sanitizeString(data.last_name)}</div>
      </div>
      <div class="field">
        <div class="field-label">Email</div>
        <div class="field-value"><a href="mailto:${sanitizeString(data.email)}">${sanitizeString(data.email)}</a></div>
      </div>
      <div class="field">
        <div class="field-label">Phone</div>
        <div class="field-value">${sanitizeString(phone)}</div>
      </div>
      <div class="field">
        <div class="field-label">Service</div>
        <div class="field-value">${sanitizeString(serviceName)}</div>
      </div>
      <div class="field">
        <div class="field-label">Preferred Date</div>
        <div class="field-value">${sanitizeString(date)}</div>
      </div>
      <div class="message-box">
        <div class="field-label">Message</div>
        <div class="field-value" style="white-space: pre-wrap;">${sanitizeString(data.message)}</div>
      </div>
    </div>
    <div class="footer">
      Submitted on ${new Date().toLocaleString('en-GB', { timeZone: 'Africa/Accra' })} (Ghana Time)
    </div>
  </div>
</body>
</html>
`;

  return { text: textBody, html: htmlBody };
}

// ══════════════════════════════════════════════════════════════
// CONTROLLER: Book Session
// ══════════════════════════════════════════════════════════════

/**
 * Handle booking form submission
 * POST /api/book-session
 */
async function bookSession(req, res, next) {
  try {
    const data = req.body;
    
    // Check honeypot fields (bot detection)
    if (data._gotcha || data.website) {
      // Silent success response to avoid tipping off bots
      console.log('🤖 Honeypot triggered — bot detected');
      return res.json({
        success: true,
        message: 'Your request has been received.'
      });
    }
    
    // Log booking request (in production, store in database)
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('  NEW BOOKING REQUEST');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`  Name:    ${data.first_name} ${data.last_name}`);
    console.log(`  Email:   ${data.email}`);
    console.log(`  Phone:   ${data.country_code || '+233'} ${data.phone || 'N/A'}`);
    console.log(`  Service: ${data.service}`);
    console.log(`  Date:    ${data.preferred_date || 'Flexible'}`);
    console.log(`  Message: ${data.message.substring(0, 100)}...`);
    console.log('═══════════════════════════════════════════════════════════════');
    
    // Send email notification
    if (transporter) {
      const { text, html } = formatBookingEmail(data);
      
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM || '"eban photos" <noreply@ebanphotos.com>',
          to: process.env.BOOKING_EMAIL || 'eban@ebanphotos.com',
          replyTo: data.email,
          subject: `New Session Request — ${data.first_name} ${data.last_name}`,
          text: text,
          html: html
        });
        
        console.log('✓ Booking notification email sent');
      } catch (emailErr) {
        console.error('Email send error:', emailErr);
        // Don't fail the request if email fails
      }
      
      // Send confirmation to client
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM || '"eban photos" <noreply@ebanphotos.com>',
          to: data.email,
          subject: 'Your Session Request — eban photos',
          text: `
Dear ${data.first_name},

Thank you for reaching out to eban photos. I've received your session request and will review it shortly.

You can expect a personal response within 24 hours.

───────────────────────────────────────────────────────────────
Your Request Details:
───────────────────────────────────────────────────────────────
Service:        ${data.service.charAt(0).toUpperCase() + data.service.slice(1)}
Preferred Date: ${data.preferred_date || 'Flexible'}

───────────────────────────────────────────────────────────────

In the meantime, feel free to explore more of my work:
→ Instagram: @ebanphotos
→ Website: ebanphotos.com

Looking forward to creating something beautiful together.

— Dadzie
   eban photos
`,
          html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: Georgia, serif; line-height: 1.8; color: #1a1e0a; background: #f4f0e4; margin: 0; padding: 20px; }
    .container { max-width: 560px; margin: 0 auto; background: white; }
    .header { background: #1a1e0a; padding: 32px; text-align: center; }
    .header h1 { color: #e8d96a; font-size: 28px; font-weight: 400; font-style: italic; margin: 0; }
    .content { padding: 40px 32px; }
    .greeting { font-size: 18px; margin-bottom: 24px; }
    .details { background: #f9f9f7; padding: 20px; border-left: 3px solid #e8d96a; margin: 24px 0; }
    .details p { margin: 8px 0; font-size: 14px; }
    .signature { margin-top: 32px; padding-top: 24px; border-top: 1px solid #eee; }
    .signature p { margin: 4px 0; }
    .footer { text-align: center; padding: 20px; font-size: 12px; color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>eban photos</h1>
    </div>
    <div class="content">
      <p class="greeting">Dear ${sanitizeString(data.first_name)},</p>
      <p>Thank you for reaching out to eban photos. I've received your session request and will review it shortly.</p>
      <p>You can expect a personal response within <strong>24 hours</strong>.</p>
      
      <div class="details">
        <p><strong>Service:</strong> ${sanitizeString(data.service.charAt(0).toUpperCase() + data.service.slice(1))}</p>
        <p><strong>Preferred Date:</strong> ${sanitizeString(data.preferred_date || 'Flexible')}</p>
      </div>
      
      <p>In the meantime, feel free to explore more of my work on <a href="https://instagram.com/ebanphotos">Instagram</a>.</p>
      
      <p>Looking forward to creating something beautiful together.</p>
      
      <div class="signature">
        <p><em>— Dadzie</em></p>
        <p style="color: #888; font-size: 14px;">eban photos</p>
      </div>
    </div>
    <div class="footer">
      © 2026 eban photos · Tarkwa, Ghana
    </div>
  </div>
</body>
</html>
`
        });
        
        console.log('✓ Client confirmation email sent');
      } catch (emailErr) {
        console.error('Client email send error:', emailErr);
      }
    }
    
    res.json({
      success: true,
      message: 'Your session request has been received. Expect a response within 24 hours.'
    });
    
  } catch (err) {
    next(err);
  }
}

module.exports = {
  bookSession
};
