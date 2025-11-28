/**
 * Cryptographic utilities for SAML operations
 */

import crypto from 'crypto';
import zlib from 'zlib';
import { SignedXml } from 'xml-crypto';
import { DOMParser } from '@xmldom/xmldom';

/**
 * Generates a random unique identifier for SAML requests
 */
export function generateUniqueId(): string {
  return `_${crypto.randomBytes(21).toString('hex')}`;
}

/**
 * Generates a timestamp in ISO 8601 format for SAML
 */
export function generateTimestamp(date: Date = new Date()): string {
  return date.toISOString();
}

/**
 * Validates a certificate format
 */
export function validateCertificate(cert: string): string {
  // Remove headers, footers, and whitespace
  const cleaned = cert
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');

  return cleaned;
}

/**
 * Formats a certificate with proper headers
 */
export function formatCertificate(cert: string): string {
  const cleaned = validateCertificate(cert);
  return `-----BEGIN CERTIFICATE-----\n${cleaned}\n-----END CERTIFICATE-----`;
}

/**
 * Signs XML using RSA-SHA256
 */
export function signXml(xml: string, privateKey: string, options: {
  prefix?: string;
  location?: { reference: string; action: 'append' | 'prepend' | 'before' | 'after' };
}): string {
  const sig = new SignedXml({
    privateKey: privateKey,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });

  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
  });

  sig.computeSignature(xml, options);
  return sig.getSignedXml();
}

/**
 * Verifies XML signature using a certificate
 */
export function verifyXmlSignature(xml: string, cert: string | string[]): boolean {
  const doc = new DOMParser().parseFromString(xml);
  const signatures = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');

  if (signatures.length === 0) {
    return false;
  }

  const certs = Array.isArray(cert) ? cert : [cert];

  for (const certificate of certs) {
    try {
      const sig = new SignedXml();
      sig.publicCert = formatCertificate(certificate);
      sig.loadSignature(signatures[0]);

      const valid = sig.checkSignature(xml);
      if (valid) {
        return true;
      }
    } catch (error) {
      // Try next certificate
      continue;
    }
  }

  return false;
}

/**
 * Deflates and base64 encodes data for SAML HTTP-Redirect binding
 */
export function deflateAndEncode(data: string): string {
  const deflated = zlib.deflateRawSync(Buffer.from(data, 'utf8'));
  return deflated.toString('base64');
}

/**
 * Decodes and inflates data from SAML HTTP-Redirect binding
 */
export function decodeAndInflate(data: string): string {
  const decoded = Buffer.from(data, 'base64');
  const inflated = zlib.inflateRawSync(decoded);
  return inflated.toString('utf8');
}

/**
 * Decodes base64 SAML response (HTTP-POST binding)
 */
export function decodeBase64(data: string): string {
  return Buffer.from(data, 'base64').toString('utf8');
}

/**
 * Encodes data to base64 (HTTP-POST binding)
 */
export function encodeBase64(data: string): string {
  return Buffer.from(data, 'utf8').toString('base64');
}

