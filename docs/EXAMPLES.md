# Examples

Practical examples for common SAML authentication scenarios.

## Table of Contents

- [Basic Setup](#basic-setup)
- [Database Integration](#database-integration)
- [Role-Based Access Control](#role-based-access-control)
- [Multi-Tenant Applications](#multi-tenant-applications)
- [API Authentication](#api-authentication)
- [Custom User Attributes](#custom-user-attributes)
- [Error Handling](#error-handling)
- [Testing](#testing)

## Basic Setup

Minimal working example:

```typescript
import express from 'express';
import session from 'express-session';
import { createSAMLMiddleware } from '@bozzltron/express-saml';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false,
}));

const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: 'http://localhost:3000/auth/saml/callback',
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
});

app.get('/auth/saml/login', saml.authenticate());
app.post('/auth/saml/callback', saml.callback());
app.get('/dashboard', saml.requireAuth(), (req, res) => {
  res.json({ user: req.samlUser });
});

app.listen(3000);
```

## Database Integration

### With PostgreSQL

```typescript
import { Pool } from 'pg';

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    // Find or create user
    const result = await db.query(`
      INSERT INTO users (email, first_name, last_name, saml_name_id)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (email) 
      DO UPDATE SET 
        last_login = NOW(),
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name
      RETURNING id, email, first_name, last_name
    `, [profile.email, profile.firstName, profile.lastName, profile.nameID]);
    
    const user = result.rows[0];
    
    // Store user ID in session
    req.session.userId = user.id;
    
    // Update last login
    await db.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );
    
    console.log('User logged in:', user.email);
    return true;
  },
});
```

### With MongoDB

```typescript
import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGO_URL!);
await client.connect();
const db = client.db('myapp');

const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    const users = db.collection('users');
    
    // Upsert user
    const result = await users.findOneAndUpdate(
      { email: profile.email },
      {
        $set: {
          email: profile.email,
          firstName: profile.firstName,
          lastName: profile.lastName,
          samlNameId: profile.nameID,
          lastLogin: new Date(),
        },
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      {
        upsert: true,
        returnDocument: 'after',
      }
    );
    
    req.session.userId = result._id;
    return true;
  },
});
```

### With Prisma

```typescript
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    const user = await prisma.user.upsert({
      where: { email: profile.email },
      update: {
        firstName: profile.firstName,
        lastName: profile.lastName,
        lastLogin: new Date(),
      },
      create: {
        email: profile.email!,
        firstName: profile.firstName,
        lastName: profile.lastName,
        samlNameId: profile.nameID,
        lastLogin: new Date(),
      },
    });
    
    req.session.userId = user.id;
    return true;
  },
});
```

## Role-Based Access Control

Extract roles from SAML attributes and enforce access:

```typescript
interface UserWithRoles extends SAMLProfile {
  roles: string[];
}

const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    // Extract roles from SAML attributes
    const roles = (profile.attributes.roles as string[]) || 
                  (profile.attributes['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] as string[]) ||
                  [];
    
    // Store user with roles
    req.session.user = {
      ...profile,
      roles: Array.isArray(roles) ? roles : [roles],
    };
    
    return true;
  },
});

// Middleware to check roles
function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.session.user as UserWithRoles;
    
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const hasRole = user.roles.some(role => allowedRoles.includes(role));
    
    if (!hasRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Usage
app.get('/admin', saml.requireAuth(), requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only area' });
});

app.get('/dashboard', saml.requireAuth(), requireRole('user', 'admin'), (req, res) => {
  res.json({ message: 'User dashboard' });
});
```

## Multi-Tenant Applications

Support multiple IdPs for different tenants:

```typescript
import { SAMLMiddleware } from '@bozzltron/express-saml';

// Store SAML configurations per tenant
const samlConfigs = new Map<string, SAMLMiddleware>();

// Initialize configurations
async function initializeTenantSAML() {
  const tenants = await db.query('SELECT * FROM tenants WHERE saml_enabled = true');
  
  for (const tenant of tenants.rows) {
    const saml = new SAMLMiddleware({
      issuer: `${tenant.subdomain}-app`,
      callbackUrl: `https://${tenant.subdomain}.myapp.com/auth/saml/callback`,
      entryPoint: tenant.saml_entry_point,
      idpCert: tenant.saml_idp_cert,
      
      onAuth: async (profile, req, res) => {
        const user = await db.query(
          'INSERT INTO users (tenant_id, email, first_name, last_name) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, email) DO UPDATE SET last_login = NOW() RETURNING *',
          [tenant.id, profile.email, profile.firstName, profile.lastName]
        );
        
        req.session.userId = user.rows[0].id;
        req.session.tenantId = tenant.id;
        return true;
      },
    });
    
    samlConfigs.set(tenant.subdomain, saml);
  }
}

// Middleware to get SAML config for current tenant
function getTenantSAML(req: Request): SAMLMiddleware {
  const subdomain = req.hostname.split('.')[0];
  const saml = samlConfigs.get(subdomain);
  
  if (!saml) {
    throw new Error('SAML not configured for this tenant');
  }
  
  return saml;
}

// Routes
app.get('/auth/saml/login', (req, res) => {
  const saml = getTenantSAML(req);
  return saml.authenticate()(req, res, () => {});
});

app.post('/auth/saml/callback', (req, res) => {
  const saml = getTenantSAML(req);
  return saml.callback()(req, res, () => {});
});

app.get('/dashboard', (req, res, next) => {
  const saml = getTenantSAML(req);
  return saml.requireAuth()(req, res, next);
}, (req, res) => {
  res.json({ user: req.samlUser });
});
```

## API Authentication

Use SAML for API endpoints with JWT tokens:

```typescript
import jwt from 'jsonwebtoken';

const saml = createSAMLMiddleware({
  issuer: 'my-api',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    // Generate JWT token
    const token = jwt.sign(
      {
        sub: profile.nameID,
        email: profile.email,
        name: `${profile.firstName} ${profile.lastName}`,
        roles: profile.attributes.roles,
      },
      process.env.JWT_SECRET!,
      { expiresIn: '24h' }
    );
    
    // Return token instead of redirecting
    return res.json({
      success: true,
      token,
      user: profile,
    });
  },
});

// Middleware to verify JWT
function verifyJWT(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// API routes
app.get('/api/profile', verifyJWT, (req, res) => {
  res.json(req.user);
});

app.get('/api/data', verifyJWT, (req, res) => {
  res.json({ data: 'Protected data' });
});
```

## Custom User Attributes

Handle custom attributes from your IdP:

```typescript
const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    // Extract custom attributes
    const customAttrs = profile.attributes;
    
    const user = {
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
      
      // Standard attributes
      department: customAttrs.department as string,
      jobTitle: customAttrs.jobTitle as string,
      phoneNumber: customAttrs.phoneNumber as string,
      
      // Custom attributes (adjust based on your IdP)
      employeeId: customAttrs.employeeId as string,
      office: customAttrs.office as string,
      manager: customAttrs.manager as string,
      
      // Azure AD specific
      objectId: customAttrs['http://schemas.microsoft.com/identity/claims/objectidentifier'] as string,
      tenantId: customAttrs['http://schemas.microsoft.com/identity/claims/tenantid'] as string,
      
      // Okta specific
      groups: customAttrs.groups as string[],
    };
    
    // Store in database
    await db.users.upsert({
      where: { email: user.email },
      update: user,
      create: user,
    });
    
    req.session.user = user;
    return true;
  },
});
```

## Error Handling

Comprehensive error handling:

```typescript
const saml = createSAMLMiddleware({
  issuer: 'my-app',
  callbackUrl: process.env.SAML_CALLBACK_URL!,
  entryPoint: process.env.SAML_ENTRY_POINT!,
  idpCert: process.env.SAML_IDP_CERT!,
  
  onAuth: async (profile, req, res) => {
    try {
      // Validate required fields
      if (!profile.email) {
        throw new Error('Email not provided by IdP');
      }
      
      // Check if user is allowed
      const allowedDomains = ['company.com', 'partner.com'];
      const domain = profile.email.split('@')[1];
      
      if (!allowedDomains.includes(domain)) {
        throw new Error('Email domain not allowed');
      }
      
      // Create/update user
      const user = await db.users.upsert({
        where: { email: profile.email },
        update: {
          firstName: profile.firstName,
          lastName: profile.lastName,
          lastLogin: new Date(),
        },
        create: {
          email: profile.email,
          firstName: profile.firstName,
          lastName: profile.lastName,
          status: 'active',
        },
      });
      
      // Check user status
      if (user.status === 'suspended') {
        throw new Error('User account is suspended');
      }
      
      req.session.userId = user.id;
      return true;
      
    } catch (error) {
      // Log error
      console.error('Authentication error:', error);
      
      // Send notification
      await sendAdminNotification({
        type: 'auth_error',
        user: profile.email,
        error: error.message,
      });
      
      // Rethrow to trigger onError handler
      throw error;
    }
  },
  
  onError: (error, req, res) => {
    console.error('SAML Error:', error);
    
    const errorCode = (error as any).code;
    
    // Handle specific error types
    switch (errorCode) {
      case 'INVALID_SIGNATURE':
        return res.status(401).render('error', {
          title: 'Authentication Error',
          message: 'Invalid signature from identity provider',
        });
        
      case 'EXPIRED':
        return res.status(401).render('error', {
          title: 'Session Expired',
          message: 'Your authentication session has expired. Please try again.',
        });
        
      case 'AUDIENCE_MISMATCH':
        return res.status(401).render('error', {
          title: 'Configuration Error',
          message: 'Application configuration error. Please contact support.',
        });
        
      default:
        return res.status(500).render('error', {
          title: 'Authentication Failed',
          message: 'An error occurred during authentication. Please try again.',
          supportEmail: 'support@company.com',
        });
    }
  },
});
```

## Testing

### Unit Testing with Mock SAML Responses

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { SAMLService } from '@bozzltron/express-saml';

describe('SAML Authentication', () => {
  let samlService: SAMLService;
  
  beforeEach(() => {
    samlService = new SAMLService({
      issuer: 'test-app',
      callbackUrl: 'http://localhost:3000/callback',
      entryPoint: 'http://localhost:8080/sso',
      idpCert: process.env.TEST_IDP_CERT!,
      validateSignature: false, // Disable for testing
    });
  });
  
  it('should parse valid SAML response', async () => {
    const mockResponse = createMockSAMLResponse({
      nameID: 'user@example.com',
      attributes: {
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
      },
    });
    
    const profile = await samlService.validateResponse(mockResponse);
    
    expect(profile.email).toBe('user@example.com');
    expect(profile.firstName).toBe('John');
    expect(profile.lastName).toBe('Doe');
  });
  
  it('should reject expired SAML response', async () => {
    const expiredResponse = createMockSAMLResponse({
      nameID: 'user@example.com',
      notOnOrAfter: new Date(Date.now() - 1000), // Expired 1 second ago
    });
    
    await expect(
      samlService.validateResponse(expiredResponse)
    ).rejects.toThrow('EXPIRED');
  });
});

function createMockSAMLResponse(options: any): string {
  const xml = `<?xml version="1.0"?>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject>
          <saml:NameID>${options.nameID}</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
          ${Object.entries(options.attributes || {}).map(([key, value]) => `
            <saml:Attribute Name="${key}">
              <saml:AttributeValue>${value}</saml:AttributeValue>
            </saml:Attribute>
          `).join('')}
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>`;
  
  return Buffer.from(xml).toString('base64');
}
```

### Integration Testing

```typescript
import request from 'supertest';
import app from '../app';

describe('SAML Integration', () => {
  it('should redirect to IdP on login', async () => {
    const response = await request(app)
      .get('/auth/saml/login')
      .expect(302);
    
    expect(response.headers.location).toContain(process.env.SAML_ENTRY_POINT);
    expect(response.headers.location).toContain('SAMLRequest=');
  });
  
  it('should require authentication for protected routes', async () => {
    await request(app)
      .get('/dashboard')
      .expect(302); // Redirect to login
  });
  
  it('should allow access to protected routes with valid session', async () => {
    const agent = request.agent(app);
    
    // Simulate SAML callback
    await agent
      .post('/auth/saml/callback')
      .send({ SAMLResponse: mockValidResponse })
      .expect(302);
    
    // Should now have access
    await agent
      .get('/dashboard')
      .expect(200);
  });
});
```

## More Examples

For more examples, see the [`src/example/`](../src/example/) directory in the repository.

## Need Help?

- 📖 [Full Documentation](../README.md)
- 🔧 [Setup Guide](./SETUP_GUIDE.md)
- 🐛 [Report Issues](https://github.com/bozzltron/express-saml/issues)

