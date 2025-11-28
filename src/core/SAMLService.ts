/**
 * Core SAML Service
 * Handles SAML request generation, response validation, and assertion parsing
 */

import { parseStringPromise } from 'xml2js';
import type {
  SAMLConfig,
  SAMLRequest,
  SAMLAssertion,
  SAMLProfile,
  SAMLError,
} from '../types/index.js';
import {
  generateUniqueId,
  generateTimestamp,
  deflateAndEncode,
  decodeBase64,
  verifyXmlSignature,
  signXml,
} from '../utils/crypto.js';

export class SAMLService {
  private config: Required<SAMLConfig>;

  constructor(config: SAMLConfig) {
    // Set defaults for optional configuration
    this.config = {
      ...config,
      signRequest: config.signRequest ?? false,
      wantAssertionsSigned: config.wantAssertionsSigned ?? true,
      validateSignature: config.validateSignature ?? true,
      clockSkew: config.clockSkew ?? 0,
      nameIdFormat:
        config.nameIdFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      additionalParams: config.additionalParams ?? {},
      forceAuthn: config.forceAuthn ?? false,
      passive: config.passive ?? false,
      logoutUrl: config.logoutUrl ?? config.entryPoint,
      privateKey: config.privateKey ?? '',
      cert: config.cert ?? '',
      identifierFormat:
        config.identifierFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    };

    this.validateConfig();
  }

  /**
   * Validates the SAML configuration
   */
  private validateConfig(): void {
    const required = ['issuer', 'entryPoint', 'callbackUrl', 'idpCert'];

    for (const field of required) {
      if (!this.config[field as keyof SAMLConfig]) {
        throw new Error(`SAML configuration missing required field: ${field}`);
      }
    }

    if (this.config.signRequest && !this.config.privateKey) {
      throw new Error('signRequest requires privateKey to be configured');
    }
  }

  /**
   * Generates a SAML authentication request
   */
  public generateAuthRequest(): SAMLRequest {
    const id = generateUniqueId();
    const issueInstant = generateTimestamp();

    const xml = `<?xml version="1.0"?>
<samlp:AuthnRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="${this.config.callbackUrl}"
  Destination="${this.config.entryPoint}"
  ${this.config.forceAuthn ? 'ForceAuthn="true"' : ''}
  ${this.config.passive ? 'IsPassive="true"' : ''}>
  <saml:Issuer>${this.config.issuer}</saml:Issuer>
  <samlp:NameIDPolicy 
    Format="${this.config.nameIdFormat}"
    AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

    // Sign if required
    const finalXml = this.config.signRequest && this.config.privateKey
      ? signXml(xml, this.config.privateKey, {
          location: { reference: "//*[local-name(.)='Issuer']", action: 'after' },
        })
      : xml;

    // Deflate and encode for HTTP-Redirect binding
    const encoded = deflateAndEncode(finalXml);

    return {
      xml: finalXml,
      encoded,
      id,
    };
  }

  /**
   * Validates and parses a SAML response
   */
  public async validateResponse(samlResponse: string): Promise<SAMLProfile> {
    try {
      // Decode the base64 response
      const xml = decodeBase64(samlResponse);

      // Validate signature if required
      if (this.config.validateSignature) {
        const signatureValid = verifyXmlSignature(xml, this.config.idpCert);

        if (!signatureValid) {
          throw this.createError('Invalid signature', 'INVALID_SIGNATURE');
        }
      }

      // Parse assertion
      const assertion = await this.parseAssertion(xml);

      // Validate timing
      this.validateTiming(assertion);

      // Validate audience
      this.validateAudience(assertion);

      // Convert to profile
      return this.assertionToProfile(assertion);
    } catch (error) {
      if ((error as SAMLError).code) {
        throw error;
      }
      throw this.createError(
        `Failed to validate SAML response: ${(error as Error).message}`,
        'VALIDATION_ERROR',
        error
      );
    }
  }

  /**
   * Parses a SAML assertion from XML
   */
  private async parseAssertion(xml: string): Promise<SAMLAssertion> {
    const parsed = await parseStringPromise(xml, {
      tagNameProcessors: [(name) => name.replace(/^.*:/, '')],
      explicitArray: false,
    });

    const response = parsed.Response;
    const assertion = response.Assertion;

    if (!assertion) {
      throw this.createError('No assertion found in response', 'NO_ASSERTION');
    }

    // Extract NameID
    const subject = assertion.Subject;
    const nameID = subject?.NameID?._ || subject?.NameID || '';

    const nameIDFormat = subject?.NameID?.$?.Format;

    // Extract session index
    const authnStatement = assertion.AuthnStatement;
    const sessionIndex = authnStatement?.$?.SessionIndex;

    // Extract attributes
    const attributes: Record<string, string | string[]> = {};
    const attributeStatement = assertion.AttributeStatement;

    if (attributeStatement?.Attribute) {
      const attrs = Array.isArray(attributeStatement.Attribute)
        ? attributeStatement.Attribute
        : [attributeStatement.Attribute];

      for (const attr of attrs) {
        const name = attr.$?.Name || attr.$.FriendlyName;
        const values = attr.AttributeValue;

        if (Array.isArray(values)) {
          attributes[name] = values.map((v: unknown) => (typeof v === 'object' && v !== null && '_' in v ? (v as { _: string })._ : String(v)));
        } else if (typeof values === 'object' && values !== null && '_' in values) {
          attributes[name] = (values as { _: string })._;
        } else {
          attributes[name] = String(values);
        }
      }
    }

    // Extract conditions
    const conditions = assertion.Conditions?.$;
    const issueInstant = response.$?.IssueInstant
      ? new Date(response.$.IssueInstant)
      : undefined;
    const notOnOrAfter = conditions?.NotOnOrAfter ? new Date(conditions.NotOnOrAfter) : undefined;

    return {
      nameID,
      nameIDFormat,
      sessionIndex,
      attributes,
      issueInstant,
      notOnOrAfter,
      conditions: {
        notBefore: conditions?.NotBefore ? new Date(conditions.NotBefore) : undefined,
        notOnOrAfter,
        audience: assertion.Conditions?.AudienceRestriction?.Audience,
      },
    };
  }

  /**
   * Validates assertion timing (NotBefore, NotOnOrAfter)
   */
  private validateTiming(assertion: SAMLAssertion): void {
    const now = Date.now();
    const skew = this.config.clockSkew;

    if (assertion.conditions?.notBefore) {
      const notBefore = assertion.conditions.notBefore.getTime() - skew;
      if (now < notBefore) {
        throw this.createError('Assertion not yet valid', 'NOT_YET_VALID');
      }
    }

    if (assertion.conditions?.notOnOrAfter) {
      const notOnOrAfter = assertion.conditions.notOnOrAfter.getTime() + skew;
      if (now >= notOnOrAfter) {
        throw this.createError('Assertion has expired', 'EXPIRED');
      }
    }
  }

  /**
   * Validates audience restriction
   */
  private validateAudience(assertion: SAMLAssertion): void {
    if (assertion.conditions?.audience) {
      const audiences = Array.isArray(assertion.conditions.audience)
        ? assertion.conditions.audience
        : [assertion.conditions.audience];

      if (!audiences.includes(this.config.issuer)) {
        throw this.createError(
          `Audience mismatch. Expected: ${this.config.issuer}`,
          'AUDIENCE_MISMATCH'
        );
      }
    }
  }

  /**
   * Converts a SAML assertion to a user profile
   */
  private assertionToProfile(assertion: SAMLAssertion): SAMLProfile {
    const profile: SAMLProfile = {
      nameID: assertion.nameID,
      attributes: assertion.attributes,
      sessionIndex: assertion.sessionIndex,
    };

    // Extract common attributes
    const attrs = assertion.attributes;

    // Try various common attribute names for email
    profile.email =
      (attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] as string) ||
      (attrs['email'] as string) ||
      (attrs['mail'] as string) ||
      (attrs['emailAddress'] as string);

    // Try various common attribute names for first name
    profile.firstName =
      (attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'] as string) ||
      (attrs['firstName'] as string) ||
      (attrs['givenName'] as string) ||
      (attrs['given_name'] as string);

    // Try various common attribute names for last name
    profile.lastName =
      (attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'] as string) ||
      (attrs['lastName'] as string) ||
      (attrs['surname'] as string) ||
      (attrs['sn'] as string) ||
      (attrs['family_name'] as string);

    return profile;
  }

  /**
   * Generates a SAML logout request
   */
  public generateLogoutRequest(nameID: string, sessionIndex?: string): SAMLRequest {
    const id = generateUniqueId();
    const issueInstant = generateTimestamp();

    const xml = `<?xml version="1.0"?>
<samlp:LogoutRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${this.config.logoutUrl}">
  <saml:Issuer>${this.config.issuer}</saml:Issuer>
  <saml:NameID Format="${this.config.nameIdFormat}">${nameID}</saml:NameID>
  ${sessionIndex ? `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>` : ''}
</samlp:LogoutRequest>`;

    const encoded = deflateAndEncode(xml);

    return {
      xml,
      encoded,
      id,
    };
  }

  /**
   * Gets the SSO login URL with encoded SAML request
   */
  public getLoginUrl(): string {
    const request = this.generateAuthRequest();
    const params = new URLSearchParams({
      SAMLRequest: request.encoded,
      ...this.config.additionalParams,
    });

    return `${this.config.entryPoint}?${params.toString()}`;
  }

  /**
   * Creates a structured SAML error
   */
  private createError(message: string, code: string, details?: unknown): SAMLError {
    const error = new Error(message) as SAMLError;
    error.code = code;
    error.details = details;
    return error;
  }
}

