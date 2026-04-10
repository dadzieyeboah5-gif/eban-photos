# eban photos — Secure Full-Stack Website

A production-ready photography website with enterprise-level security, Paystack payment integration, and premium content protection.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND                                  │
│              (GitHub Pages or Render Static)                     │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│   │   HTML/CSS  │    │  JavaScript │    │   Assets    │         │
│   │  (Nonce'd)  │    │  (Secure)   │    │  (Images)   │         │
│   └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS API Calls
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         BACKEND                                  │
│                    (Render Web Service)                          │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Security Layer                        │   │
│   │  • Helmet.js (CSP, HSTS, XSS Protection)                │   │
│   │  • Rate Limiting (per-endpoint)                          │   │
│   │  • CORS (restricted origins)                             │   │
│   │  • Input Validation (Joi)                                │   │
│   │  • CSRF Protection                                       │   │
│   │  • JWT Authentication                                    │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │ Payment  │  │ Booking  │  │  Images  │  │ Session  │       │
│   │  Routes  │  │  Routes  │  │  Routes  │  │  Routes  │       │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│        │             │             │             │               │
│        ▼             ▼             ▼             ▼               │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│   │ Paystack │  │ Nodemailer│  │ Premium  │  │   JWT    │       │
│   │   API    │  │   SMTP   │  │  Files   │  │  Tokens  │       │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Features

### 1. Content Security Policy (CSP)
- **Dynamic nonces** — Every page load generates a unique nonce
- **No `unsafe-inline`** — All inline scripts/styles require valid nonces
- **Restricted sources** — Only trusted domains allowed

### 2. HTTP Security Headers (Helmet.js)
- **HSTS** — Forces HTTPS with 1-year max-age
- **X-Content-Type-Options** — Prevents MIME sniffing
- **X-Frame-Options** — Prevents clickjacking
- **Referrer-Policy** — Controls referrer information

### 3. Rate Limiting
| Endpoint | Limit | Window |
|----------|-------|--------|
| General API | 100 requests | 15 minutes |
| Payment | 10 requests | 10 minutes |
| Booking | 5 requests | 1 hour |
| Session verify | 5 requests | 5 minutes |

### 4. Input Validation (Joi)
- **All inputs validated** — Names, emails, phone numbers, dates
- **Strict patterns** — Regex validation for sensitive fields
- **Sanitization** — XSS prevention on all user input

### 5. Payment Security
- **Secret key server-side only** — Never exposed to frontend
- **Server-side verification** — Paystack API validates every payment
- **JWT access tokens** — Signed tokens for premium content
- **Webhook support** — Double verification via webhooks

### 6. Premium Content Protection
- **Path traversal prevention** — Strict filename validation
- **JWT or signed URLs** — No direct file access
- **Time-limited URLs** — Signed URLs expire after 1 hour

---

## 📁 Project Structure

```
eban-photos-backend/
├── server.js                 # Main Express server
├── package.json              # Dependencies
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
├── render.yaml               # Render deployment config
│
├── routes/
│   ├── payment.js            # POST /api/pay, /api/verify-payment
│   ├── booking.js            # POST /api/book-session
│   ├── images.js             # GET /api/premium-image/:filename
│   └── session.js            # POST /api/verify-session
│
├── controllers/
│   ├── paymentController.js  # Paystack integration
│   ├── bookingController.js  # Email notifications
│   ├── imageController.js    # Secure file serving
│   └── sessionController.js  # JWT verification
│
├── middleware/
│   ├── rateLimiter.js        # Rate limiting
│   ├── csrf.js               # CSRF protection
│   ├── validation.js         # Joi schemas
│   ├── auth.js               # JWT handling
│   └── errorHandler.js       # Error middleware
│
└── premium-images/           # (Add your premium images here)
```

---

## 🚀 Deployment Guide

### Step 1: Backend Setup (Render)

1. **Create a new Web Service** on [Render](https://render.com)

2. **Connect your GitHub repository** containing the backend code

3. **Configure build settings:**
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Environment:** Node

4. **Set environment variables** in Render dashboard:

```bash
# Required
NODE_ENV=production
PORT=3000
FRONTEND_URL=https://yourusername.github.io/eban-photos
PAYSTACK_PUBLIC_KEY=pk_live_xxxxxxxxxxxx
PAYSTACK_SECRET_KEY=sk_live_xxxxxxxxxxxx

# Generate these (run in terminal):
# node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=<64-char-hex-string>
SIGNED_URL_SECRET=<32-char-hex-string>

# Optional (for email notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
BOOKING_EMAIL=eban@ebanphotos.com
```

5. **Deploy** — Render will automatically build and deploy

6. **Note your backend URL** (e.g., `https://eban-photos-backend.onrender.com`)

---

### Step 2: Frontend Setup (GitHub Pages)

1. **Update frontend JavaScript:**

   In `index.html`, update the `API_BASE` variable:
   ```javascript
   var API_BASE = 'https://eban-photos-backend.onrender.com';
   ```

2. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Deploy frontend"
   git push origin main
   ```

3. **Enable GitHub Pages:**
   - Go to repo Settings → Pages
   - Source: Deploy from branch `main`
   - Folder: `/ (root)`

4. **Note your frontend URL** (e.g., `https://yourusername.github.io/eban-photos`)

---

### Step 3: Update CORS

Update `FRONTEND_URL` in Render environment variables to match your GitHub Pages URL.

---

### Step 4: Configure Paystack Webhook

1. Go to [Paystack Dashboard](https://dashboard.paystack.com) → Settings → API Keys & Webhooks

2. Add webhook URL:
   ```
   https://eban-photos-backend.onrender.com/api/webhook/paystack
   ```

3. Enable events: `charge.success`

---

## 🔧 API Endpoints

### Payment

```
POST /api/pay
├── Body: { email, name, paymentMethod, product }
└── Returns: { success, reference, publicKey }

POST /api/verify-payment
├── Body: { reference, product }
└── Returns: { verified, accessToken }

POST /api/webhook/paystack
└── Paystack webhook handler
```

### Booking

```
POST /api/book-session
├── Body: { first_name, last_name, email, phone, service, message }
└── Returns: { success, message }
```

### Premium Images

```
GET /api/premium-image/:filename?token=JWT
└── Returns: Image file (requires valid JWT or signed URL)

GET /api/premium-album
├── Headers: Authorization: Bearer JWT
└── Returns: { images: [{ filename, url, expires }] }
```

### Session

```
POST /api/verify-session
├── Body: { token }
└── Returns: { valid, product, email }

GET /api/csrf-token
└── Returns: { csrfToken }
```

---

## 📧 Email Configuration (Optional)

### Gmail Setup

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to [Google Account Security](https://myaccount.google.com/security)
   - Select "App passwords"
   - Generate for "Mail"
3. Use the app password as `SMTP_PASS`

### Other Providers

| Provider | SMTP_HOST | SMTP_PORT |
|----------|-----------|-----------|
| Gmail | smtp.gmail.com | 587 |
| Outlook | smtp.office365.com | 587 |
| SendGrid | smtp.sendgrid.net | 587 |
| Mailgun | smtp.mailgun.org | 587 |

---

## 🖼️ Adding Premium Images

1. Create the `premium-images/` folder in your backend:
   ```bash
   mkdir premium-images
   ```

2. Add your high-resolution images:
   ```
   premium-images/
   ├── archive-01.jpg
   ├── archive-02.jpg
   ├── archive-03.jpg
   └── ...
   ```

3. Use lowercase filenames with hyphens (e.g., `portrait-studio-01.jpg`)

4. Supported formats: `.jpg`, `.jpeg`, `.png`, `.webp`

---

## 🧪 Local Development

### Backend

```bash
cd eban-photos-backend

# Install dependencies
npm install

# Create .env file
cp .env.example .env
# Edit .env with your values

# Start development server
npm run dev
```

### Frontend

```bash
# Serve frontend locally (use any static server)
npx serve eban-photos-frontend -l 5500
```

---

## 🛡️ Security Checklist

- [x] Paystack secret key in backend only
- [x] Dynamic CSP nonces per request
- [x] Rate limiting on all endpoints
- [x] Input validation with Joi
- [x] JWT tokens for premium access
- [x] Path traversal prevention
- [x] CORS restricted to frontend domain
- [x] Helmet.js security headers
- [x] Honeypot spam protection
- [x] HTTPS enforced (via Render/GitHub Pages)

---

## 📄 License

© 2026 eban photos. All rights reserved.

---

## 🆘 Support

For technical issues:
- Check Render logs for backend errors
- Check browser console for frontend errors
- Verify environment variables are set correctly

For Paystack issues:
- Verify API keys (test vs. live)
- Check Paystack dashboard for transaction logs
- Ensure webhook is configured correctly
