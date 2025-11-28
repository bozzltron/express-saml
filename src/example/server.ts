/**
 * Example Express application with SAML authentication
 */

import express from 'express';
import session from 'express-session';
import { createSAMLMiddleware } from '../index.js';
import type { SAMLProfile } from '../types/index.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// SAML Configuration
const samlConfig = {
  // Service Provider (your application)
  issuer: process.env.SAML_ISSUER || 'express-saml-demo',
  callbackUrl: process.env.SAML_CALLBACK_URL || 'http://localhost:3000/auth/saml/callback',

  // Identity Provider
  entryPoint: process.env.SAML_ENTRY_POINT || 'https://your-idp.com/sso/saml',
  idpCert: process.env.SAML_IDP_CERT || 'YOUR_IDP_CERTIFICATE_HERE',
  logoutUrl: process.env.SAML_LOGOUT_URL,

  // Optional: Sign requests (requires privateKey)
  signRequest: process.env.SAML_SIGN_REQUEST === 'true',
  privateKey: process.env.SAML_PRIVATE_KEY,
  cert: process.env.SAML_CERT,

  // Security settings
  wantAssertionsSigned: true,
  validateSignature: true,

  // Custom success/failure redirects
  successRedirect: '/dashboard',
  failureRedirect: '/login',

  // Custom authentication handler
  onAuth: async (profile: SAMLProfile, _req: express.Request, _res: express.Response) => {
    console.log('User authenticated:', profile);

    // Here you can:
    // - Look up user in your database
    // - Create new user if doesn't exist
    // - Update last login time
    // - etc.

    // Example: Log the user attributes
    console.log('User attributes:', profile.attributes);

    // Return true to continue with default session handling
    return true;
  },

  // Custom error handler
  onError: (error: Error, _req: express.Request, res: express.Response) => {
    console.error('SAML authentication error:', error);
    res.status(401).json({
      message: 'Authentication failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  },
};

// Create SAML middleware instance
const saml = createSAMLMiddleware(samlConfig);

// Public routes
app.get('/', (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Express SAML Demo</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
          }
          h1 { color: #333; }
          .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 10px 5px;
          }
          .btn:hover { background: #0056b3; }
          .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
          code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        </style>
      </head>
      <body>
        <h1>🔐 Express SAML Demo</h1>
        <p>Modern SAML 2.0 authentication for Express.js applications.</p>
        
        <div class="info">
          <h3>Features</h3>
          <ul>
            <li>✅ SAML 2.0 compliant</li>
            <li>✅ Signature verification</li>
            <li>✅ TypeScript support</li>
            <li>✅ Session management</li>
            <li>✅ Protected routes</li>
            <li>✅ Single Logout (SLO)</li>
          </ul>
        </div>

        <a href="/auth/saml/login" class="btn">Login with SAML</a>
        <a href="/dashboard" class="btn">Go to Dashboard (Protected)</a>
        
        <h3>Quick Start</h3>
        <ol>
          <li>Configure your Identity Provider (IdP)</li>
          <li>Set environment variables in <code>.env</code></li>
          <li>Click "Login with SAML" to authenticate</li>
        </ol>

        <h3>Endpoints</h3>
        <ul>
          <li><code>GET /auth/saml/login</code> - Initiate SAML authentication</li>
          <li><code>POST /auth/saml/callback</code> - SAML assertion consumer service</li>
          <li><code>GET /auth/saml/metadata</code> - SP metadata for IdP configuration</li>
          <li><code>GET /auth/saml/logout</code> - Logout and clear session</li>
        </ul>
      </body>
    </html>
  `);
});

app.get('/login', (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Login - Express SAML</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          }
          .login-box {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
          }
          h1 { color: #333; margin-bottom: 30px; }
          .btn {
            display: inline-block;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 16px;
            transition: background 0.3s;
          }
          .btn:hover { background: #5568d3; }
        </style>
      </head>
      <body>
        <div class="login-box">
          <h1>🔐 Login Required</h1>
          <p>You need to authenticate with SAML to access this application.</p>
          <a href="/auth/saml/login" class="btn">Login with SAML SSO</a>
        </div>
      </body>
    </html>
  `);
});

// SAML Authentication Routes
app.get('/auth/saml/login', saml.authenticate());
app.post('/auth/saml/callback', saml.callback());
app.get('/auth/saml/logout', saml.logout());
app.get('/auth/saml/metadata', saml.metadata());

// Protected routes - require SAML authentication
app.get('/dashboard', saml.requireAuth(), (_req, res) => {
  const user = _req.samlUser;

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Dashboard - Express SAML</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
          }
          .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
          }
          .user-info {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #dc3545;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
          }
          .btn:hover { background: #c82333; }
          h1 { color: #333; margin: 0; }
          .attribute { padding: 8px; border-bottom: 1px solid #eee; }
          .attribute strong { display: inline-block; width: 150px; }
          pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>✨ Dashboard</h1>
          <p>Welcome, ${user?.email || user?.nameID || 'User'}!</p>
        </div>

        <div class="user-info">
          <h2>User Information</h2>
          <div class="attribute">
            <strong>Name ID:</strong>
            <span>${user?.nameID || 'N/A'}</span>
          </div>
          ${user?.email ? `
          <div class="attribute">
            <strong>Email:</strong>
            <span>${user.email}</span>
          </div>
          ` : ''}
          ${user?.firstName ? `
          <div class="attribute">
            <strong>First Name:</strong>
            <span>${user.firstName}</span>
          </div>
          ` : ''}
          ${user?.lastName ? `
          <div class="attribute">
            <strong>Last Name:</strong>
            <span>${user.lastName}</span>
          </div>
          ` : ''}
          ${user?.sessionIndex ? `
          <div class="attribute">
            <strong>Session Index:</strong>
            <span>${user.sessionIndex}</span>
          </div>
          ` : ''}
          
          <h3>All Attributes</h3>
          <pre>${JSON.stringify(user?.attributes, null, 2)}</pre>

          <a href="/auth/saml/logout" class="btn">Logout</a>
        </div>
      </body>
    </html>
  `);
});

// API endpoint example
app.get('/api/profile', saml.requireAuth(), (_req, res) => {
  res.json({
    success: true,
    user: _req.samlUser,
  });
});

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
🚀 Express SAML Demo Server

Server running on: http://localhost:${PORT}
Callback URL: ${samlConfig.callbackUrl}
Metadata URL: http://localhost:${PORT}/auth/saml/metadata

📝 Configuration:
- Issuer: ${samlConfig.issuer}
- Entry Point: ${samlConfig.entryPoint}
- Sign Requests: ${samlConfig.signRequest}

🔗 Quick Links:
- Home: http://localhost:${PORT}
- Login: http://localhost:${PORT}/auth/saml/login
- Dashboard: http://localhost:${PORT}/dashboard
- Metadata: http://localhost:${PORT}/auth/saml/metadata

⚠️  Make sure to configure your Identity Provider with the callback URL and metadata!
  `);
});

export default app;

