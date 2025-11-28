/**
 * Comprehensive integration tests for SAML Express middleware
 * These tests verify the middleware works end-to-end with Express
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import session from 'express-session';
import request from 'supertest';
import { createSAMLMiddleware } from './saml.js';
import { createMockSAMLResponse, createExpiredSAMLResponse } from '../test-helpers/mockSAML.js';

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

  describe('Full Authentication Flow', () => {
    it('should complete end-to-end authentication flow', async () => {
      const agent = request.agent(app);

      // Step 1: Try to access protected route (should redirect to login)
      const protectedResponse = await agent.get('/protected').expect(302);
      expect(protectedResponse.headers.location).toContain('/auth/saml/login');

      // Step 2: Initiate SAML login (should redirect to IdP)
      const loginResponse = await agent.get('/auth/saml/login').expect(302);
      expect(loginResponse.headers.location).toContain('http://localhost:8080/sso');
      expect(loginResponse.headers.location).toContain('SAMLRequest=');

      // Step 3: Simulate IdP callback with valid SAML response
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'Test',
        lastName: 'User',
        sessionIndex: 'session123',
      });

      const callbackResponse = await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: mockResponse })
        .expect(302);

      // Step 4: Should redirect to original protected route
      expect(callbackResponse.headers.location).toBe('/protected');

      // Step 5: Now can access protected route with user data
      const finalResponse = await agent.get('/protected').expect(200);
      expect(finalResponse.body.user).toBeDefined();
      expect(finalResponse.body.user.nameID).toBe('user@example.com');
      expect(finalResponse.body.user.email).toBe('user@example.com');
      expect(finalResponse.body.user.firstName).toBe('Test');
      expect(finalResponse.body.user.lastName).toBe('User');
      expect(finalResponse.body.user.sessionIndex).toBe('session123');
    });

    it('should persist session across multiple requests', async () => {
      const agent = request.agent(app);

      // Authenticate
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      // Make multiple requests - session should persist
      const response1 = await agent.get('/protected').expect(200);
      const response2 = await agent.get('/dashboard').expect(200);
      const response3 = await agent.get('/protected').expect(200);

      // All should have the same user
      expect(response1.body.user.nameID).toBe('user@example.com');
      expect(response2.body.user.nameID).toBe('user@example.com');
      expect(response3.body.user.nameID).toBe('user@example.com');
    });

    it('should handle logout and clear session', async () => {
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
      expect(logoutResponse.headers.location).toBeDefined();

      // Should no longer have access
      await agent.get('/protected').expect(302);
    });
  });

  describe('Route Protection', () => {
    it('should protect routes with requireAuth middleware', async () => {
      // Without authentication
      await request(app).get('/protected').expect(302);

      // With authentication
      const agent = request.agent(app);
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
      });

      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);
      await agent.get('/protected').expect(200);
    });

    it('should allow public routes without authentication', async () => {
      const response = await request(app).get('/public').expect(200);
      expect(response.body.message).toBe('public route');
    });

    it('should set req.samlUser on protected routes', async () => {
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
  });

  describe('SAML Request Generation', () => {
    it('should generate valid SAML login URL', async () => {
      const response = await request(app).get('/auth/saml/login').expect(302);

      expect(response.headers.location).toContain('http://localhost:8080/sso');
      expect(response.headers.location).toContain('SAMLRequest=');

      // Parse URL to verify SAMLRequest parameter
      const url = new URL(response.headers.location);
      const samlRequest = url.searchParams.get('SAMLRequest');
      expect(samlRequest).toBeTruthy();
      expect(samlRequest!.length).toBeGreaterThan(0);
    });

    it('should store returnTo URL in session', async () => {
      const agent = request.agent(app);

      // Access protected route
      await agent.get('/protected').expect(302);

      // Should redirect to login, then to IdP
      const loginResponse = await agent.get('/auth/saml/login').expect(302);
      expect(loginResponse.headers.location).toContain('http://localhost:8080/sso');
    });
  });

  describe('SAML Response Handling', () => {
    it('should parse valid SAML response and extract user profile', async () => {
      const mockResponse = createMockSAMLResponse({
        nameID: 'user@example.com',
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
        attributes: {
          department: 'Engineering',
          role: 'developer',
        },
      });

      const agent = request.agent(app);
      await agent.post('/auth/saml/callback').send({ SAMLResponse: mockResponse }).expect(302);

      const response = await agent.get('/protected').expect(200);
      expect(response.body.user.nameID).toBe('user@example.com');
      expect(response.body.user.email).toBe('user@example.com');
      expect(response.body.user.firstName).toBe('John');
      expect(response.body.user.lastName).toBe('Doe');
      expect(response.body.user.attributes.department).toBe('Engineering');
      expect(response.body.user.attributes.role).toBe('developer');
    });

    it('should handle missing SAMLResponse', async () => {
      const response = await request(app).post('/auth/saml/callback').send({}).expect(302);
      expect(response.headers.location).toBe('/login');
    });

    it('should handle invalid SAML response', async () => {
      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: 'invalid-base64' })
        .expect(302);

      expect(response.headers.location).toBe('/login');
    });

    it('should reject expired SAML responses', async () => {
      const expiredResponse = createExpiredSAMLResponse({
        nameID: 'user@example.com',
      });

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: expiredResponse })
        .expect(302);

      // Should redirect to failure
      expect(response.headers.location).toBe('/login');
    });
  });

  describe('Custom Callbacks', () => {
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

    it('should call onError callback on authentication failure', async () => {
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
  });

  describe('Metadata Endpoint', () => {
    it('should return valid SP metadata XML', async () => {
      const response = await request(app).get('/auth/saml/metadata').expect(200);

      expect(response.headers['content-type']).toContain('application/xml');
      expect(response.text).toContain('EntityDescriptor');
      expect(response.text).toContain('SPSSODescriptor');
      expect(response.text).toContain('test-sp');
      expect(response.text).toContain('http://localhost:3000/auth/saml/callback');
      expect(response.text).toContain('AssertionConsumerService');
      expect(response.text).toContain('HTTP-POST');
    });

    it('should include correct entity ID and callback URL', async () => {
      const response = await request(app).get('/auth/saml/metadata').expect(200);

      const xml = response.text;
      expect(xml).toContain('entityID="test-sp"');
      expect(xml).toContain('Location="http://localhost:3000/auth/saml/callback"');
    });
  });

  describe('Redirect Behavior', () => {
    it('should redirect to successRedirect after successful auth', async () => {
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

    it('should redirect to returnTo URL if present in session', async () => {
      const agent = request.agent(app);

      // Try to access protected route (sets returnTo)
      await agent.get('/protected').expect(302);

      // Authenticate
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

  describe('Session Management', () => {
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
  });
});

