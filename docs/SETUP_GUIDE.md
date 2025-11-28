# Setup Guide

Complete guide to setting up SAML authentication with express-saml.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Identity Provider Configuration](#identity-provider-configuration)
- [Application Configuration](#application-configuration)
- [Testing](#testing)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required
- Node.js >= 18.0.0
- Express.js application
- Access to a SAML 2.0 Identity Provider (IdP)

### Recommended
- Session middleware (express-session)
- HTTPS in production
- Basic understanding of SAML 2.0 concepts

## Installation

### 1. Install Package

```bash
npm install @bozzltron/express-saml express-session
```

### 2. TypeScript Users

TypeScript types are included, but you may need additional types:

```bash
npm install --save-dev @types/express @types/express-session
```

## Identity Provider Configuration

### Step 1: Create SAML Application

In your Identity Provider (Okta, Auth0, Azure AD, etc.):

1. Create a new SAML 2.0 application
2. Configure the following:

   **Entity ID / Issuer:**
   ```
   your-application-name
   ```

   **ACS URL / Callback URL:**
   ```
   https://yourdomain.com/auth/saml/callback
   ```

   **Binding:**
   ```
   HTTP-POST
   ```

   **Name ID Format:**
   ```
   urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
   ```

### Step 2: Configure Attributes

Map these attributes from your IdP to SAML assertions:

| IdP Attribute | SAML Attribute Name | Required |
|---------------|---------------------|----------|
| Email | `email` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | Yes |
| First Name | `firstName` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | No |
| Last Name | `lastName` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | No |

### Step 3: Get IdP Information

From your IdP, obtain:

1. **SSO URL / Entry Point**
   - Example: `https://your-idp.com/app/myapp/sso/saml`

2. **IdP Certificate**
   - Download as PEM format
   - Remove headers and line breaks for environment variable

3. **Logout URL** (optional)
   - Example: `https://your-idp.com/app/myapp/slo/saml`

### Provider-Specific Guides

<details>
<summary>Okta</summary>

1. Go to **Applications** → **Create App Integration**
2. Select **SAML 2.0**
3. Enter app name and logo
4. Configure SAML Settings:
   - Single sign on URL: `https://yourdomain.com/auth/saml/callback`
   - Audience URI: `your-app-name`
   - Name ID format: `EmailAddress`
5. Configure Attribute Statements:
   - `email` → `user.email`
   - `firstName` → `user.firstName`
   - `lastName` → `user.lastName`
6. Finish and view **Setup Instructions** for:
   - Identity Provider Single Sign-On URL
   - X.509 Certificate
</details>

<details>
<summary>Auth0</summary>

1. Go to **Applications** → **Create Application**
2. Select **Regular Web Applications**
3. Go to **Addons** → Enable **SAML2 WEB APP**
4. Configure:
   ```json
   {
     "audience": "your-app-name",
     "recipient": "https://yourdomain.com/auth/saml/callback",
     "mappings": {
       "email": "email",
       "given_name": "firstName",
       "family_name": "lastName"
     }
   }
   ```
5. Download certificate from **Usage** tab
6. Note the **Identity Provider Login URL**
</details>

<details>
<summary>Azure AD</summary>

1. Go to **Azure Active Directory** → **Enterprise Applications**
2. **New application** → **Create your own application**
3. Select **Integrate any other application (Non-gallery)**
4. Go to **Single sign-on** → Select **SAML**
5. Configure:
   - Identifier (Entity ID): `your-app-name`
   - Reply URL: `https://yourdomain.com/auth/saml/callback`
6. Configure User Attributes:
   - `email` → `user.mail`
   - `firstName` → `user.givenname`
   - `lastName` → `user.surname`
7. Download **Certificate (Base64)**
8. Note **Login URL** from section 4
</details>

## Application Configuration

### Step 1: Environment Variables

Create a `.env` file:

```bash
# Application
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-random-secret-key-min-32-chars

# SAML Configuration
SAML_ISSUER=your-application-name
SAML_CALLBACK_URL=https://yourdomain.com/auth/saml/callback
SAML_ENTRY_POINT=https://your-idp.com/sso/saml
SAML_LOGOUT_URL=https://your-idp.com/slo/saml

# IdP Certificate (remove line breaks, keep as one line)
SAML_IDP_CERT="MIIDXTCCAkWgAwIBAgIJAKs...full certificate here...xyz=="

# Optional: Request Signing (requires generating SP certificates)
SAML_SIGN_REQUEST=false
# SAML_PRIVATE_KEY="MIIEvQIBADANBgk..."
# SAML_CERT="MIIDXTCCAkWgAwI..."
```

### Step 2: Server Setup

```typescript
// server.ts
import express from 'express';
import session from 'express-session';
import { createSAMLMiddleware } from '@bozzltron/express-saml';

const app = express();

// Required middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax',
  },
}));

// SAML middleware
const saml = createSAMLMiddleware({
  issuer: process.env.SAML_ISSUER!,
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  logoutUrl: process.env.SAML_LOGOUT_URL,
  
  // Security settings
  validateSignature: true,
  wantAssertionsSigned: true,
  
  // Redirects
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  
  // Custom handler for user management
  onAuth: async (profile, req, res) => {
    // Look up or create user in your database
    const user = await db.users.findOrCreate({
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
    });
    
    req.session.userId = user.id;
    return true; // Continue with default handling
  },
});

// SAML routes
app.get('/auth/saml/login', saml.authenticate());
app.post('/auth/saml/callback', saml.callback());
app.get('/auth/saml/logout', saml.logout());
app.get('/auth/saml/metadata', saml.metadata());

// Protected routes
app.get('/dashboard', saml.requireAuth(), (req, res) => {
  res.json({ user: req.samlUser });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

### Step 3: TypeScript Configuration (Optional)

If using TypeScript, extend Express Request type:

```typescript
// types/express.d.ts
import { SAMLProfile } from '@bozzltron/express-saml';

declare global {
  namespace Express {
    interface Request {
      samlUser?: SAMLProfile;
    }
  }
}
```

## Testing

### Local Development with Mock IdP

For local testing without a real IdP:

1. Use [saml-idp](https://github.com/mcguinness/saml-idp) for a mock IdP
2. Or use online SAML test services
3. Configure with http://localhost:3000 URLs

### Testing Checklist

- [ ] Can initiate login (`/auth/saml/login`)
- [ ] Redirects to IdP
- [ ] Can authenticate at IdP
- [ ] Callback receives SAML response
- [ ] User profile extracted correctly
- [ ] Session created
- [ ] Can access protected routes
- [ ] Logout works
- [ ] Metadata endpoint accessible

### Debug Mode

Enable detailed logging:

```typescript
const saml = createSAMLMiddleware({
  // ... config
  onAuth: async (profile, req, res) => {
    console.log('✅ Authentication successful');
    console.log('Profile:', JSON.stringify(profile, null, 2));
    return true;
  },
  onError: (error, req, res) => {
    console.error('❌ Authentication failed:', error);
    res.status(401).send('Auth failed');
  },
});
```

## Production Deployment

### Security Checklist

- [ ] HTTPS enabled (required!)
- [ ] Secure session secret (min 32 random characters)
- [ ] `cookie.secure: true` in session config
- [ ] Environment variables properly set
- [ ] Certificate validation enabled
- [ ] Signature verification enabled
- [ ] Clock skew configured appropriately
- [ ] Error messages don't leak sensitive info
- [ ] Logging doesn't expose secrets

### Environment Variables

Store these securely:

```bash
# Use AWS Secrets Manager, Azure Key Vault, etc.
aws secretsmanager get-secret-value --secret-id prod/saml/idp-cert

# Or use encrypted environment variables
heroku config:set SAML_IDP_CERT="$(cat cert.pem)"
```

### Metadata Configuration

Provide your SP metadata to the IdP admin:

```
https://yourdomain.com/auth/saml/metadata
```

### Monitoring

Monitor these metrics:

- SAML authentication success rate
- Authentication latency
- Failed login attempts
- Certificate expiration dates

### Load Balancing

If using load balancers:

- Use sticky sessions OR
- Use shared session store (Redis, Memcached)

```typescript
import RedisStore from 'connect-redis';
import { createClient } from 'redis';

const redisClient = createClient();
await redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  // ... other config
}));
```

## Troubleshooting

### Common Issues

#### "Invalid signature" Error

**Cause:** IdP certificate is incorrect or expired

**Solution:**
1. Verify certificate format (no headers, no line breaks)
2. Check certificate hasn't expired
3. Ensure you have the correct certificate from IdP
4. Try disabling validation temporarily (dev only):
   ```typescript
   validateSignature: false // NEVER in production!
   ```

#### "Assertion has expired" Error

**Cause:** Time difference between SP and IdP

**Solution:** Add clock skew tolerance:
```typescript
clockSkew: 300000, // 5 minutes
```

#### "Audience mismatch" Error

**Cause:** Issuer doesn't match IdP configuration

**Solution:** Ensure `issuer` in your config matches exactly what's configured in IdP

#### User Profile Missing Attributes

**Cause:** IdP not sending expected attributes

**Solution:**
1. Check IdP attribute mapping configuration
2. Log the raw attributes to see what's available:
   ```typescript
   onAuth: async (profile, req, res) => {
     console.log('All attributes:', profile.attributes);
     return true;
   },
   ```

### Debug Steps

1. **Check IdP Configuration**
   - Verify ACS URL matches exactly
   - Check entity ID matches
   - Confirm attributes are mapped

2. **Validate Certificate**
   ```bash
   openssl x509 -in cert.pem -text -noout
   ```

3. **Test Metadata**
   ```bash
   curl https://yourdomain.com/auth/saml/metadata
   ```

4. **Enable Verbose Logging**
   ```typescript
   onError: (error, req, res) => {
     console.error('Error details:', {
       message: error.message,
       code: (error as any).code,
       stack: error.stack,
     });
   },
   ```

5. **Use SAML Tracer**
   - Install [SAML-tracer](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/) browser extension
   - Capture SAML flow
   - Inspect requests and responses

## Next Steps

- [API Documentation](../README.md#api-documentation)
- [Advanced Usage Examples](./EXAMPLES.md)
- [Security Best Practices](./SECURITY.md)
- [Contributing Guide](../CONTRIBUTING.md)

## Support

- 📖 [Full Documentation](../README.md)
- 🐛 [Report Issues](https://github.com/bozzltron/express-saml/issues)
- 💬 [Ask Questions](https://github.com/bozzltron/express-saml/discussions)

