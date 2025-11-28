# @bozzltron/express-saml

Modern SAML 2.0 authentication middleware for Express.js with TypeScript support.

## ✨ Features

- 🔐 **SAML 2.0 Compliant** - Full implementation of SAML 2.0 specification
- 🛡️ **Secure by Default** - Signature verification, certificate validation, timing checks
- 📝 **TypeScript First** - Complete type definitions and IntelliSense support
- 🎯 **Simple API** - Easy-to-use middleware pattern for Express
- 🔄 **Single Logout (SLO)** - Support for identity provider initiated logout
- 📋 **Metadata Generation** - Automatic SP metadata for IdP configuration
- ⚡ **Modern Stack** - Uses latest JavaScript/TypeScript standards
- 🧪 **Well Tested** - Comprehensive test coverage
- 📖 **Excellent Documentation** - Clear examples and guides

## 📦 Installation

```bash
npm install @bozzltron/express-saml
```

## 🚀 Quick Start

### 1. Basic Setup

```typescript
import express from 'express';
import session from 'express-session';
import { createSAMLMiddleware } from '@bozzltron/express-saml';

const app = express();

// Required: Session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true }
}));

// Create SAML middleware
const saml = createSAMLMiddleware({
  // Your application (Service Provider)
  issuer: 'my-app',
  callbackUrl: 'https://myapp.com/auth/saml/callback',
  
  // Identity Provider
  entryPoint: 'https://idp.com/sso/saml',
  idpCert: process.env.SAML_IDP_CERT,
  
  // Where to redirect after authentication
  successRedirect: '/dashboard',
  failureRedirect: '/login',
});

// Setup SAML routes
app.get('/auth/saml/login', saml.authenticate());
app.post('/auth/saml/callback', saml.callback());
app.get('/auth/saml/logout', saml.logout());
app.get('/auth/saml/metadata', saml.metadata());

// Protect routes
app.get('/dashboard', saml.requireAuth(), (req, res) => {
  res.json({ user: req.samlUser });
});

app.listen(3000);
```

### 2. Environment Configuration

Create a `.env` file:

```bash
# Service Provider
SAML_ISSUER=my-application
SAML_CALLBACK_URL=https://myapp.com/auth/saml/callback

# Identity Provider
SAML_ENTRY_POINT=https://idp.com/sso/saml
SAML_IDP_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"

# Optional: Sign requests
SAML_SIGN_REQUEST=false
SAML_PRIVATE_KEY="..."
```

## 📚 API Documentation

### SAMLMiddleware Options

```typescript
interface SAMLMiddlewareOptions {
  // Required: Service Provider Configuration
  issuer: string;                    // Your app's entity ID
  callbackUrl: string;               // Where SAML responses are posted
  entryPoint: string;                // IdP SSO URL
  idpCert: string | string[];        // IdP certificate(s)
  
  // Optional: Security
  signRequest?: boolean;             // Sign authentication requests
  privateKey?: string;               // SP private key (if signing)
  cert?: string;                     // SP certificate
  validateSignature?: boolean;       // Verify response signatures (default: true)
  wantAssertionsSigned?: boolean;    // Require signed assertions (default: true)
  clockSkew?: number;                // Time tolerance in ms (default: 0)
  
  // Optional: Behavior
  successRedirect?: string;          // Where to go after login (default: '/')
  failureRedirect?: string;          // Where to go on error (default: '/login')
  sessionProperty?: string;          // Session key for user (default: 'samlUser')
  forceAuthn?: boolean;              // Force re-authentication
  passive?: boolean;                 // Don't prompt for credentials
  
  // Optional: Callbacks
  onAuth?: (profile, req, res) => Promise<boolean | void>;
  onError?: (error, req, res) => void;
  
  // Optional: Logout
  logoutUrl?: string;                // IdP logout URL
}
```

### Methods

#### `authenticate()`
Initiates SAML authentication by redirecting to the Identity Provider.

```typescript
app.get('/login', saml.authenticate());
```

#### `callback()`
Handles SAML responses from the Identity Provider (Assertion Consumer Service).

```typescript
app.post('/auth/callback', saml.callback());
```

#### `requireAuth()`
Middleware to protect routes - requires active SAML session.

```typescript
app.get('/protected', saml.requireAuth(), (req, res) => {
  // req.samlUser is available here
});
```

#### `logout()`
Clears session and optionally initiates Single Logout with IdP.

```typescript
app.get('/logout', saml.logout());
```

#### `metadata()`
Provides SP metadata XML for IdP configuration.

```typescript
app.get('/metadata', saml.metadata());
```

### User Profile

After successful authentication, `req.samlUser` contains:

```typescript
interface SAMLProfile {
  nameID: string;                              // User identifier
  email?: string;                              // Email address
  firstName?: string;                          // First name
  lastName?: string;                           // Last name
  sessionIndex?: string;                       // Session index for SLO
  attributes: Record<string, string | string[]>; // All IdP attributes
}
```

## 🔧 Advanced Usage

### Custom Authentication Handler

```typescript
const saml = createSAMLMiddleware({
  // ... other options
  onAuth: async (profile, req, res) => {
    // Custom logic: create/update user in database
    const user = await db.users.findOrCreate({
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
    });
    
    // Store custom session data
    req.session.userId = user.id;
    req.session.roles = profile.attributes.roles;
    
    // Return true to continue with default session handling
    return true;
  },
});
```

### Custom Error Handler

```typescript
const saml = createSAMLMiddleware({
  // ... other options
  onError: (error, req, res) => {
    console.error('SAML Error:', error);
    
    // Log to monitoring service
    logger.error('SAML authentication failed', { error, user: req.ip });
    
    // Custom error page
    res.status(401).render('auth-error', { 
      message: 'Authentication failed. Please try again.' 
    });
  },
});
```

### Request Signing

For enhanced security, sign authentication requests:

```typescript
const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: 'https://myapp.com/auth/callback',
  entryPoint: 'https://idp.com/sso',
  idpCert: process.env.IDP_CERT,
  
  // Enable request signing
  signRequest: true,
  privateKey: fs.readFileSync('./certs/private-key.pem', 'utf8'),
  cert: fs.readFileSync('./certs/certificate.pem', 'utf8'),
});
```

### Multiple IdP Certificates

Support certificate rotation by providing multiple certificates:

```typescript
const saml = createSAMLMiddleware({
  // ... other options
  idpCert: [
    process.env.IDP_CERT_CURRENT,
    process.env.IDP_CERT_OLD,  // Still valid during rotation
  ],
});
```

## 🔐 Security Best Practices

1. **Always use HTTPS** in production
2. **Validate signatures** (enabled by default)
3. **Use secure session configuration**:
   ```typescript
   app.use(session({
     secret: process.env.SESSION_SECRET,
     resave: false,
     saveUninitialized: false,
     cookie: {
       secure: true,      // HTTPS only
       httpOnly: true,    // Prevent XSS
       sameSite: 'lax',   // CSRF protection
       maxAge: 86400000   // 24 hours
     }
   }));
   ```
4. **Rotate certificates** regularly
5. **Set clock skew** appropriately (0-5 minutes)
6. **Use environment variables** for sensitive data
7. **Monitor authentication failures**
8. **Keep dependencies updated**

## 🧪 Testing

The package includes comprehensive tests that **prove the middleware works with Express**:

### Test Coverage

- ✅ **Unit Tests** - Core SAML logic (request generation, response validation, crypto utilities)
- ✅ **Integration Tests** - Full Express middleware integration with real Express apps
- ✅ **End-to-End Tests** - Complete authentication flows from login to protected routes

### What the Tests Prove

The integration tests verify:
- ✅ Middleware integrates correctly with Express routing
- ✅ Sessions are created and persisted correctly
- ✅ Route protection (`requireAuth()`) works as expected
- ✅ SAML requests are generated and redirects work
- ✅ SAML responses are parsed and user profiles extracted
- ✅ Logout clears sessions properly
- ✅ Custom callbacks (`onAuth`, `onError`) are invoked
- ✅ Redirect behavior (successRedirect, returnTo) works correctly
- ✅ Error handling works gracefully

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch

# Run specific test file
npm test saml.integration.test.ts
```

See [TESTING.md](./TESTING.md) for detailed testing documentation.

## 📖 Examples

See the [`src/example/`](./src/example/) directory for complete working examples:

- **Basic Authentication** - Simple SAML integration
- **Database Integration** - User creation and lookup
- **Role-Based Access** - Using SAML attributes for authorization
- **Multi-Tenant** - Supporting multiple IdPs

## 🔄 SAML Flow

1. **User visits protected route**
2. **Redirect to `/auth/saml/login`** (if not authenticated)
3. **Middleware generates SAML AuthnRequest**
4. **User redirected to IdP** for authentication
5. **User authenticates at IdP**
6. **IdP posts SAML Response** to callback URL
7. **Middleware validates response** (signature, timing, audience)
8. **User session created** with profile data
9. **User redirected to original route**

## 🛠️ Identity Provider Setup

### Configure your IdP with:

1. **Entity ID (Issuer)**: Your `issuer` value
2. **ACS URL**: Your `callbackUrl` (POST binding)
3. **SP Metadata**: From `/auth/saml/metadata` endpoint
4. **Name ID Format**: Email address (default)
5. **Attributes to send**:
   - Email
   - First Name
   - Last Name
   - Any custom attributes

### Popular IdPs:

- **Okta**: [SAML Setup Guide](https://developer.okta.com/docs/guides/saml-application-setup/)
- **Auth0**: [SAML Configuration](https://auth0.com/docs/authenticate/protocols/saml)
- **Azure AD**: [Enterprise SSO](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/add-application-portal-setup-sso)
- **OneLogin**: [SAML Apps](https://developers.onelogin.com/saml)

## 📝 Common Issues

### Certificate Format Issues

Ensure certificates are properly formatted:

```typescript
// Remove headers and whitespace
const cert = process.env.IDP_CERT
  .replace(/-----BEGIN CERTIFICATE-----/, '')
  .replace(/-----END CERTIFICATE-----/, '')
  .replace(/\s/g, '');
```

### Clock Skew Errors

If you get timing errors, add clock skew tolerance:

```typescript
const saml = createSAMLMiddleware({
  // ... other options
  clockSkew: 300000, // 5 minutes tolerance
});
```

### Signature Validation Failures

1. Verify certificate is correct
2. Check certificate hasn't expired
3. Ensure IdP is signing responses
4. Try disabling validation temporarily for debugging (NOT in production)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT © [Michael Bosworth](https://github.com/bozzltron)

## 🙏 Credits

Built with modern web standards and inspired by:
- [passport-saml](https://github.com/node-saml/passport-saml)
- [SAML 2.0 Specification](http://docs.oasis-open.org/security/saml/v2.0/)

## 📞 Support

- 🐛 [Report Issues](https://github.com/bozzltron/express-saml/issues)
- 📧 Email: michael@bozzltron.com
- 💬 [Discussions](https://github.com/bozzltron/express-saml/discussions)

---

Made with ❤️ by [Michael Bosworth](https://github.com/bozzltron)
