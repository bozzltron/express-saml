/**
 * SAML Configuration Types
 */

export interface SAMLConfig {
  /** Service Provider Entity ID (your application) */
  issuer: string;

  /** Identity Provider SSO URL where authentication requests are sent */
  entryPoint: string;

  /** URL where SAML responses are posted (must match IdP configuration) */
  callbackUrl: string;

  /** Identity Provider's public certificate for signature verification */
  idpCert: string | string[];

  /** Service Provider private key for signing requests (optional) */
  privateKey?: string;

  /** Service Provider certificate (optional) */
  cert?: string;

  /** Sign authentication requests (default: false) */
  signRequest?: boolean;

  /** Require signed SAML responses (default: true) */
  wantAssertionsSigned?: boolean;

  /** Validate SAML response signatures (default: true) */
  validateSignature?: boolean;

  /** Clock tolerance in milliseconds for time validation (default: 0) */
  clockSkew?: number;

  /** Name ID format (default: emailAddress) */
  nameIdFormat?: string;

  /** Additional SAML request parameters */
  additionalParams?: Record<string, string>;

  /** Force authentication even if user has valid session at IdP */
  forceAuthn?: boolean;

  /** Allow IdP to reuse existing authentication */
  passive?: boolean;

  /** Logout URL at Identity Provider */
  logoutUrl?: string;

  /** Identifier format for requests */
  identifierFormat?: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' | 
                     'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' |
                     'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' |
                     string;
}

export interface SAMLAssertion {
  /** User identifier from the Identity Provider */
  nameID: string;

  /** Format of the name identifier */
  nameIDFormat?: string;

  /** Session index for logout */
  sessionIndex?: string;

  /** User attributes from IdP */
  attributes: Record<string, string | string[]>;

  /** Authentication instant */
  issueInstant?: Date;

  /** Assertion expiration */
  notOnOrAfter?: Date;

  /** Conditions for assertion validity */
  conditions?: {
    notBefore?: Date;
    notOnOrAfter?: Date;
    audience?: string;
  };
}

export interface SAMLRequest {
  /** The SAML authentication request XML */
  xml: string;

  /** Base64 encoded and deflated request for HTTP-Redirect binding */
  encoded: string;

  /** Unique identifier for this request */
  id: string;
}

export interface SAMLResponse {
  /** Original SAML response (base64 encoded) */
  raw: string;

  /** Decoded XML */
  xml: string;

  /** Parsed assertion data */
  assertion: SAMLAssertion;

  /** Whether the response signature was valid */
  signatureValid: boolean;
}

export interface SAMLProfile {
  /** User identifier */
  nameID: string;

  /** User email (if available in attributes) */
  email?: string;

  /** User's first name */
  firstName?: string;

  /** User's last name */
  lastName?: string;

  /** All attributes from IdP */
  attributes: Record<string, string | string[]>;

  /** Session index for logout */
  sessionIndex?: string;
}

export interface SAMLError extends Error {
  code: string;
  details?: unknown;
}

