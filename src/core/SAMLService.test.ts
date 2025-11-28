/**
 * Tests for SAMLService
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SAMLService } from './SAMLService.js';
import type { SAMLConfig } from '../types/index.js';

describe('SAMLService', () => {
  let config: SAMLConfig;

  beforeEach(() => {
    config = {
      issuer: 'test-sp',
      callbackUrl: 'http://localhost:3000/callback',
      entryPoint: 'http://localhost:8080/sso',
      idpCert: 'FAKE_CERTIFICATE_FOR_TESTING',
    };
  });

  describe('constructor', () => {
    it('should create instance with valid config', () => {
      const service = new SAMLService(config);
      expect(service).toBeInstanceOf(SAMLService);
    });

    it('should throw error with missing required fields', () => {
      const invalidConfig = { ...config };
      delete (invalidConfig as Partial<SAMLConfig>).issuer;

      expect(() => new SAMLService(invalidConfig as SAMLConfig)).toThrow(
        'SAML configuration missing required field: issuer'
      );
    });

    it('should throw error when signRequest is true but no privateKey', () => {
      const invalidConfig = { ...config, signRequest: true };

      expect(() => new SAMLService(invalidConfig)).toThrow(
        'signRequest requires privateKey to be configured'
      );
    });
  });

  describe('generateAuthRequest', () => {
    it('should generate valid SAML authentication request', () => {
      const service = new SAMLService(config);
      const request = service.generateAuthRequest();

      expect(request).toHaveProperty('xml');
      expect(request).toHaveProperty('encoded');
      expect(request).toHaveProperty('id');

      expect(request.xml).toContain('samlp:AuthnRequest');
      expect(request.xml).toContain(config.issuer);
      expect(request.xml).toContain(config.callbackUrl);
      expect(request.id).toMatch(/^_[a-f0-9]+$/);
    });

    it('should include correct ProtocolBinding', () => {
      const service = new SAMLService(config);
      const request = service.generateAuthRequest();

      expect(request.xml).toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
    });

    it('should include ForceAuthn when configured', () => {
      const service = new SAMLService({ ...config, forceAuthn: true });
      const request = service.generateAuthRequest();

      expect(request.xml).toContain('ForceAuthn="true"');
    });

    it('should include IsPassive when configured', () => {
      const service = new SAMLService({ ...config, passive: true });
      const request = service.generateAuthRequest();

      expect(request.xml).toContain('IsPassive="true"');
    });

    it('should generate base64 encoded request', () => {
      const service = new SAMLService(config);
      const request = service.generateAuthRequest();

      expect(request.encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
  });

  describe('getLoginUrl', () => {
    it('should generate login URL with SAMLRequest parameter', () => {
      const service = new SAMLService(config);
      const loginUrl = service.getLoginUrl();

      expect(loginUrl).toContain(config.entryPoint);
      expect(loginUrl).toContain('SAMLRequest=');
    });

    it('should include additional parameters', () => {
      const service = new SAMLService({
        ...config,
        additionalParams: {
          RelayState: '/dashboard',
          custom: 'value',
        },
      });
      const loginUrl = service.getLoginUrl();

      expect(loginUrl).toContain('RelayState=%2Fdashboard');
      expect(loginUrl).toContain('custom=value');
    });
  });

  describe('generateLogoutRequest', () => {
    it('should generate valid SAML logout request', () => {
      const service = new SAMLService(config);
      const request = service.generateLogoutRequest('user@example.com', 'session123');

      expect(request.xml).toContain('samlp:LogoutRequest');
      expect(request.xml).toContain('user@example.com');
      expect(request.xml).toContain('session123');
      expect(request.id).toMatch(/^_[a-f0-9]+$/);
    });

    it('should work without session index', () => {
      const service = new SAMLService(config);
      const request = service.generateLogoutRequest('user@example.com');

      expect(request.xml).toContain('samlp:LogoutRequest');
      expect(request.xml).toContain('user@example.com');
      expect(request.xml).not.toContain('SessionIndex');
    });
  });

  describe('validateResponse', () => {
    it('should throw error for invalid base64', async () => {
      const service = new SAMLService({ ...config, validateSignature: false });

      await expect(service.validateResponse('invalid-base64!@#')).rejects.toThrow();
    });

    it('should throw error when no assertion found', async () => {
      const service = new SAMLService({ ...config, validateSignature: false });
      const emptyResponse = Buffer.from('<Response></Response>').toString('base64');

      await expect(service.validateResponse(emptyResponse)).rejects.toThrow('NO_ASSERTION');
    });
  });
});

