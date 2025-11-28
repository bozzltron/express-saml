/**
 * Tests for crypto utilities
 */

import { describe, it, expect } from 'vitest';
import {
  generateUniqueId,
  generateTimestamp,
  validateCertificate,
  formatCertificate,
  deflateAndEncode,
  decodeAndInflate,
  encodeBase64,
  decodeBase64,
} from './crypto.js';

describe('Crypto Utilities', () => {
  describe('generateUniqueId', () => {
    it('should generate unique ID with underscore prefix', () => {
      const id = generateUniqueId();
      expect(id).toMatch(/^_[a-f0-9]+$/);
      expect(id.length).toBeGreaterThan(20);
    });

    it('should generate different IDs each time', () => {
      const id1 = generateUniqueId();
      const id2 = generateUniqueId();
      expect(id1).not.toBe(id2);
    });
  });

  describe('generateTimestamp', () => {
    it('should generate ISO 8601 timestamp', () => {
      const timestamp = generateTimestamp();
      expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it('should accept custom date', () => {
      const date = new Date('2024-01-15T10:30:00.000Z');
      const timestamp = generateTimestamp(date);
      expect(timestamp).toBe('2024-01-15T10:30:00.000Z');
    });
  });

  describe('certificate handling', () => {
    const testCert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKs
Some certificate content here
-----END CERTIFICATE-----`;

    it('should validate and clean certificate', () => {
      const cleaned = validateCertificate(testCert);
      expect(cleaned).not.toContain('-----BEGIN CERTIFICATE-----');
      expect(cleaned).not.toContain('-----END CERTIFICATE-----');
      expect(cleaned).not.toMatch(/\s/);
    });

    it('should format certificate with headers', () => {
      const formatted = formatCertificate(testCert);
      expect(formatted).toContain('-----BEGIN CERTIFICATE-----');
      expect(formatted).toContain('-----END CERTIFICATE-----');
    });
  });

  describe('base64 encoding/decoding', () => {
    const testData = 'Hello, SAML!';

    it('should encode to base64', () => {
      const encoded = encodeBase64(testData);
      expect(encoded).toBe(Buffer.from(testData).toString('base64'));
    });

    it('should decode from base64', () => {
      const encoded = encodeBase64(testData);
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(testData);
    });

    it('should handle round-trip encoding', () => {
      const original = 'Test data with special chars: äöü @#$%';
      const encoded = encodeBase64(original);
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(original);
    });
  });

  describe('deflate and inflate', () => {
    const testData = '<samlp:AuthnRequest>Test SAML Request</samlp:AuthnRequest>';

    it('should deflate and encode data', () => {
      const encoded = deflateAndEncode(testData);
      expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(encoded.length).toBeLessThan(testData.length);
    });

    it('should handle round-trip deflate/inflate', () => {
      const encoded = deflateAndEncode(testData);
      const decoded = decodeAndInflate(encoded);
      expect(decoded).toBe(testData);
    });

    it('should compress data effectively', () => {
      const largeData = testData.repeat(10);
      const encoded = deflateAndEncode(largeData);
      expect(encoded.length).toBeLessThan(largeData.length);
    });
  });
});

