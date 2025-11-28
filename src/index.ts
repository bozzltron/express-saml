/**
 * Express SAML - Modern SAML 2.0 authentication for Express.js
 * 
 * @packageDocumentation
 */

export { SAMLService } from './core/SAMLService.js';
export { SAMLMiddleware, createSAMLMiddleware } from './middleware/saml.js';
export type { SAMLMiddlewareOptions } from './middleware/saml.js';
export type {
  SAMLConfig,
  SAMLAssertion,
  SAMLRequest,
  SAMLResponse,
  SAMLProfile,
  SAMLError,
} from './types/index.js';
export {
  generateUniqueId,
  generateTimestamp,
  deflateAndEncode,
  decodeAndInflate,
  decodeBase64,
  encodeBase64,
} from './utils/crypto.js';

