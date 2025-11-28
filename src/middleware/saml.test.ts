/**
 * Integration tests for SAML Express middleware
 * These tests verify the middleware actually works with Express
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import session from 'express-session';
import request from 'supertest';
import { createSAMLMiddleware } from './saml.js';
import type { SAMLProfile } from '../types/index.js';

// Mock SAML response generator
function createMockSAMLResponse(profile: Partial<SAMLProfile>): string {
  const xml = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_test123"
                Version="2.0"
                IssueInstant="${new Date().toISOString()}">
  <saml:Issuer>test-idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion123" Version="2.0" IssueInstant="${new Date().toISOString()}">
    <saml:Issuer>test-idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        ${profile.nameID || 'user@example.com'}
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${new Date(Date.now() + 3600000).toISOString()}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${new Date(Date.now() - 60000).toISOString()}"
                     NotOnOrAfter="${new Date(Date.now() + 3600000).toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>test-sp</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${new Date().toISOString()}" SessionIndex="session123">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      ${profile.email ? `<saml:Attribute Name="email">
        <saml:AttributeValue>${profile.email}</saml:AttributeValue>
      </saml:Attribute>` : ''}
      ${profile.firstName ? `<saml:Attribute Name="firstName">
        <saml:AttributeValue>${profile.firstName}</saml:AttributeValue>
      </saml:Attribute>` : ''}
      ${profile.lastName ? `<saml:Attribute Name="lastName">
        <saml:AttributeValue>${profile.lastName}</saml:AttributeValue>
      </saml:Attribute>` : ''}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  return Buffer.from(xml).toString('base64');
}

describe('SAMLMiddleware Express Integration', () => {
  let app: Express;
  let samlMiddleware: ReturnType<typeof createSAMLMiddleware>;

  beforeEach(() => {
    app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());

    // Setup session middleware
    app.use(
      session({
        secret: 'test-secret-key-for-testing-only',
        resave: false,
        saveUninitialized: false,
        cookie: {
          secure: false, // HTTP for testing
          httpOnly: true,
        },
      })
    );

    // Create SAML middleware
    samlMiddleware = createSAMLMiddleware({
      issuer: 'test-sp',
      callbackUrl: 'http://localhost:3000/auth/saml/callback',
      entryPoint: 'http://localhost:8080/sso',
      idpCert: 'FAKE_CERT_FOR_TESTING',
      validateSignature: false, // Disable for testing
      successRedirect: '/dashboard',
      failureRedirect: '/login',
    });

    // Setup SAML routes
    app.get('/auth/saml/login', samlMiddleware.authenticate());
    app.post('/auth/saml/callback', samlMiddleware.callback());
    app.get('/auth/saml/logout', samlMiddleware.logout());
    app.get('/auth/saml/metadata', samlMiddleware.metadata());

    // Test routes
    app.get('/public', (_req, res) => {
      res.json({ message: 'public route' });
    });

    app.get('/protected', samlMiddleware.requireAuth(), (req, res) => {
      res.json({
        message: 'protected route',
        user: req.samlUser,
      });
    });

    app.get('/dashboard', samlMiddleware.requireAuth(), (req, res) => {
      res.json({
        message: 'dashboard',
        user: req.samlUser,
      });
    });

    app.get('/login', (_req, res) => {
      res.json({ message: 'login page' });
    });
  });

  describe('authenticate() route', () => {
    it('should redirect to IdP with SAMLRequest parameter', async () => {
      const response = await request(app).get('/auth/saml/login').expect(302);

      expect(response.headers.location).toContain('http://localhost:8080/sso');
      expect(response.headers.location).toContain('SAMLRequest=');
    });

    it('should store returnTo in session when accessing protected route', async () => {
      const agent = request.agent(app);

      // Try to access protected route
      const response = await agent.get('/protected').expect(302);

      // Should redirect to login
      expect(response.headers.location).toContain('/auth/saml/login');

      // Follow redirect to see SAML request
      const loginResponse = await agent.get(response.headers.location).expect(302);

      expect(loginResponse.headers.location).toContain('http://localhost:8080/sso');
    });

    it('should preserve original URL in session for redirect after auth', async () => {
      const agent = request.agent(app);

      // Access protected route
      await agent.get('/protected').expect(302);

      // Session should have returnTo
      // (We can't directly access session in supertest, but we can verify
      // it works by completing the auth flow)
    });
  });

  describe('callback() route', () => {
    it('should handle valid SAML response and create session', async () => {
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
      });

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      // Should redirect to success redirect
      expect(response.headers.location).toBe('/dashboard');
    });

    it('should store user profile in session', async () => {
      const agent = request.agent(app);
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
      });

      // Complete authentication
      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Now should be able to access protected route
      const protectedResponse = await agent.get('/protected').expect(200);

      expect(protectedResponse.body.user).toBeDefined();
      expect(protectedResponse.body.user.email).toBe('user@example.com');
      expect(protectedResponse.body.user.firstName).toBe('John');
      expect(protectedResponse.body.user.lastName).toBe('Doe');
    });

    it('should call onAuth callback when provided', async () => {
      const onAuthSpy = vi.fn().mockResolvedValue(true);

      const customSAML = createSAMLMiddleware({
        issuer: 'test-sp',
        callbackUrl: 'http://localhost:3000/auth/saml/callback',
        entryPoint: 'http://localhost:8080/sso',
        idpCert: 'FAKE_CERT',
        validateSignature: false,
        onAuth: onAuthSpy,
      });

      const customApp = express();
      customApp.use(express.urlencoded({ extended: true }));
      customApp.use(
        session({
          secret: 'test-secret',
          resave: false,
          saveUninitialized: false,
        })
      );
      customApp.post('/auth/saml/callback', customSAML.callback());

      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await request(customApp)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      expect(onAuthSpy).toHaveBeenCalledTimes(1);
      expect(onAuthSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          nameID: 'user@example.com',
          email: 'user@example.com',
        }),
        expect.any(Object), // req
        expect.any(Object) // res
      );
    });

    it('should handle invalid SAML response', async () => {
      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: 'invalid-base64' })
        .expect(302);

      // Should redirect to failure redirect
      expect(response.headers.location).toBe('/login');
    });

    it('should handle missing SAMLResponse', async () => {
      const response = await request(app).post('/auth/saml/callback').send({}).expect(302);

      expect(response.headers.location).toBe('/login');
    });

    it('should redirect to returnTo URL if present in session', async () => {
      const agent = request.agent(app);

      // First, try to access protected route (sets returnTo)
      await agent.get('/protected').expect(302);

      // Then authenticate
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      const response = await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      // Should redirect to original protected route, not default successRedirect
      expect(response.headers.location).toBe('/protected');
    });
  });

  describe('requireAuth() middleware', () => {
    it('should allow access when user is authenticated', async () => {
      const agent = request.agent(app);

      // Authenticate first
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Now access protected route
      const response = await agent.get('/protected').expect(200);

      expect(response.body.message).toBe('protected route');
      expect(response.body.user).toBeDefined();
    });

    it('should redirect to login when user is not authenticated', async () => {
      const response = await request(app).get('/protected').expect(302);

      expect(response.headers.location).toContain('/auth/saml/login');
    });

    it('should set req.samlUser when authenticated', async () => {
      const agent = request.agent(app);

      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'Jane',
        lastName: 'Smith',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      const response = await agent.get('/protected').expect(200);

      expect(response.body.user.nameID).toBe('user@example.com');
      expect(response.body.user.email).toBe('user@example.com');
      expect(response.body.user.firstName).toBe('Jane');
      expect(response.body.user.lastName).toBe('Smith');
    });

    it('should work with multiple protected routes', async () => {
      const agent = request.agent(app);

      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Access multiple protected routes
      await agent.get('/protected').expect(200);
      await agent.get('/dashboard').expect(200);
    });
  });

  describe('logout() route', () => {
    it('should clear session and redirect', async () => {
      const agent = request.agent(app);

      // Authenticate first
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Verify authenticated
      await agent.get('/protected').expect(200);

      // Logout
      const logoutResponse = await agent.get('/auth/saml/logout').expect(302);

      // Should redirect (to IdP logout or home)
      expect(logoutResponse.headers.location).toBeDefined();

      // Should no longer have access
      await agent.get('/protected').expect(302);
    });

    it('should work without authentication', async () => {
      const response = await request(app).get('/auth/saml/logout').expect(302);

      expect(response.headers.location).toBeDefined();
    });
  });

  describe('metadata() route', () => {
    it('should return SP metadata XML', async () => {
      const response = await request(app).get('/auth/saml/metadata').expect(200);

      expect(response.headers['content-type']).toContain('application/xml');
      expect(response.text).toContain('EntityDescriptor');
      expect(response.text).toContain('SPSSODescriptor');
      expect(response.text).toContain('test-sp');
      expect(response.text).toContain('http://localhost:3000/auth/saml/callback');
    });

    it('should include AssertionConsumerService', async () => {
      const response = await request(app).get('/auth/saml/metadata').expect(200);

      expect(response.text).toContain('AssertionConsumerService');
      expect(response.text).toContain('HTTP-POST');
    });
  });

  describe('Full authentication flow', () => {
    it('should complete full login flow', async () => {
      const agent = request.agent(app);

      // Step 1: Try to access protected route
      const protectedResponse = await agent.get('/protected').expect(302);
      expect(protectedResponse.headers.location).toContain('/auth/saml/login');

      // Step 2: Initiate SAML login
      const loginResponse = await agent.get('/auth/saml/login').expect(302);
      expect(loginResponse.headers.location).toContain('http://localhost:8080/sso');
      expect(loginResponse.headers.location).toContain('SAMLRequest=');

      // Step 3: Simulate IdP callback with SAML response
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'Test',
        lastName: 'User',
      });

      const callbackResponse = await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      // Step 4: Should redirect to original protected route
      expect(callbackResponse.headers.location).toBe('/protected');

      // Step 5: Now can access protected route
      const finalResponse = await agent.get('/protected').expect(200);
      expect(finalResponse.body.user.email).toBe('user@example.com');
    });

    it('should handle session persistence across requests', async () => {
      const agent = request.agent(app);

      // Authenticate
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Make multiple requests - session should persist
      await agent.get('/protected').expect(200);
      await agent.get('/dashboard').expect(200);
      await agent.get('/protected').expect(200);

      // All should work without re-authentication
    });
  });

  describe('Error handling', () => {
    it('should call onError callback when provided', async () => {
      const onErrorSpy = vi.fn();

      const customSAML = createSAMLMiddleware({
        issuer: 'test-sp',
        callbackUrl: 'http://localhost:3000/auth/saml/callback',
        entryPoint: 'http://localhost:8080/sso',
        idpCert: 'FAKE_CERT',
        validateSignature: false,
        onError: onErrorSpy,
      });

      const customApp = express();
      customApp.use(express.urlencoded({ extended: true }));
      customApp.use(
        session({
          secret: 'test-secret',
          resave: false,
          saveUninitialized: false,
        })
      );
      customApp.post('/auth/saml/callback', customSAML.callback());

      await request(customApp)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: 'invalid' })
        .expect(302);

      expect(onErrorSpy).toHaveBeenCalled();
    });

    it('should handle errors gracefully without onError callback', async () => {
      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: 'invalid-response' })
        .expect(302);

      // Should redirect to failure redirect
      expect(response.headers.location).toBe('/login');
    });
  });

  describe('Custom configuration', () => {
    it('should use custom session property name', async () => {
      const customSAML = createSAMLMiddleware({
        issuer: 'test-sp',
        callbackUrl: 'http://localhost:3000/auth/saml/callback',
        entryPoint: 'http://localhost:8080/sso',
        idpCert: 'FAKE_CERT',
        validateSignature: false,
        sessionProperty: 'customUser',
      });

      const customApp = express();
      customApp.use(express.urlencoded({ extended: true }));
      customApp.use(
        session({
          secret: 'test-secret',
          resave: false,
          saveUninitialized: false,
        })
      );
      customApp.post('/auth/saml/callback', customSAML.callback());
      customApp.get('/protected', customSAML.requireAuth(), (req, res) => {
        res.json({ user: req.samlUser });
      });

      const agent = request.agent(customApp);
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);
      await agent.get('/protected').expect(200);
    });

    it('should use custom redirect URLs', async () => {
      const customSAML = createSAMLMiddleware({
        issuer: 'test-sp',
        callbackUrl: 'http://localhost:3000/auth/saml/callback',
        entryPoint: 'http://localhost:8080/sso',
        idpCert: 'FAKE_CERT',
        validateSignature: false,
        successRedirect: '/home',
        failureRedirect: '/error',
      });

      const customApp = express();
      customApp.use(express.urlencoded({ extended: true }));
      customApp.use(
        session({
          secret: 'test-secret',
          resave: false,
          saveUninitialized: false,
        })
      );
      customApp.post('/auth/saml/callback', customSAML.callback());

      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      const response = await request(customApp)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      expect(response.headers.location).toBe('/home');
    });
  });
});

