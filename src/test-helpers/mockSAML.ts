/**
 * Test helpers for creating mock SAML responses
 */

import type { SAMLProfile } from '../types/index.js';

/**
 * Creates a valid SAML 2.0 response XML with the given profile
 */
export function createMockSAMLResponse(profile: Partial<SAMLProfile>): string {
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60000); // 1 minute ago
  const notOnOrAfter = new Date(now.getTime() + 3600000); // 1 hour from now

  const xml = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_test_response_${Date.now()}"
                Version="2.0"
                IssueInstant="${now.toISOString()}"
                Destination="http://localhost:3000/auth/saml/callback">
  <saml:Issuer>test-idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_test_assertion_${Date.now()}" 
                  Version="2.0" 
                  IssueInstant="${now.toISOString()}">
    <saml:Issuer>test-idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        ${profile.nameID || 'user@example.com'}
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter.toISOString()}"
                                      Recipient="http://localhost:3000/auth/saml/callback"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore.toISOString()}"
                     NotOnOrAfter="${notOnOrAfter.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>test-sp</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${now.toISOString()}" 
                        SessionIndex="${profile.sessionIndex || 'session123'}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      ${profile.email ? `<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>${profile.email}</saml:AttributeValue>
      </saml:Attribute>` : ''}
      ${profile.firstName ? `<saml:Attribute Name="firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>${profile.firstName}</saml:AttributeValue>
      </saml:Attribute>` : ''}
      ${profile.lastName ? `<saml:Attribute Name="lastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>${profile.lastName}</saml:AttributeValue>
      </saml:Attribute>` : ''}
      ${profile.attributes
        ? Object.entries(profile.attributes)
            .filter(([key]) => !['email', 'firstName', 'lastName'].includes(key))
            .map(
              ([key, value]) => `
      <saml:Attribute Name="${key}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        ${Array.isArray(value)
          ? value.map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`).join('\n        ')
          : `<saml:AttributeValue>${value}</saml:AttributeValue>`}
      </saml:Attribute>`
            )
            .join('')
        : ''}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  return Buffer.from(xml).toString('base64');
}

/**
 * Creates an expired SAML response for testing expiration handling
 */
export function createExpiredSAMLResponse(profile: Partial<SAMLProfile>): string {
  const now = new Date();
  const notBefore = new Date(now.getTime() - 7200000); // 2 hours ago
  const notOnOrAfter = new Date(now.getTime() - 3600000); // 1 hour ago (expired)

  const xml = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_expired_response"
                Version="2.0"
                IssueInstant="${notOnOrAfter.toISOString()}">
  <saml:Issuer>test-idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_expired_assertion" Version="2.0" IssueInstant="${notOnOrAfter.toISOString()}">
    <saml:Issuer>test-idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        ${profile.nameID || 'user@example.com'}
      </saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore.toISOString()}"
                     NotOnOrAfter="${notOnOrAfter.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>test-sp</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${notOnOrAfter.toISOString()}" SessionIndex="session123">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`;

  return Buffer.from(xml).toString('base64');
}

