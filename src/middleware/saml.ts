/**
 * Express middleware for SAML authentication
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { SAMLService } from '../core/SAMLService.js';
import type { SAMLConfig, SAMLProfile } from '../types/index.js';

// Extend Express Request to include SAML user
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      samlUser?: SAMLProfile;
    }
  }
}

// Type for session with custom properties
interface SAMLSession {
  returnTo?: string;
  [key: string]: unknown;
}

export interface SAMLMiddlewareOptions extends SAMLConfig {
  /**
   * Custom function to handle successful authentication
   * Return false to prevent default session handling
   */
  onAuth?: (profile: SAMLProfile, req: Request, res: Response) => Promise<boolean | void> | boolean | void;

  /**
   * Custom function to handle authentication errors
   */
  onError?: (error: Error, req: Request, res: Response) => void;

  /**
   * Where to redirect after successful authentication (default: '/')
   */
  successRedirect?: string;

  /**
   * Where to redirect after failed authentication (default: '/login')
   */
  failureRedirect?: string;

  /**
   * Session property name to store user (default: 'samlUser')
   */
  sessionProperty?: string;
}

export class SAMLMiddleware {
  private samlService: SAMLService;
  private options: SAMLMiddlewareOptions;

  constructor(options: SAMLMiddlewareOptions) {
    this.options = {
      successRedirect: '/',
      failureRedirect: '/login',
      sessionProperty: 'samlUser',
      ...options,
    };

    this.samlService = new SAMLService(options);
  }

  /**
   * Initiates SAML authentication by redirecting to IdP
   */
  public authenticate(): RequestHandler {
    return (req: Request, res: Response) => {
      try {
        // Store the original URL to redirect back after auth
        if (req.session) {
          (req.session as unknown as SAMLSession).returnTo = req.originalUrl || req.url;
        }

        const loginUrl = this.samlService.getLoginUrl();
        res.redirect(loginUrl);
      } catch (error) {
        this.handleError(error as Error, req, res);
      }
    };
  }

  /**
   * Handles SAML callback (assertion consumer service)
   */
  public callback(): RequestHandler {
    return async (req: Request, res: Response) => {
      try {
        const samlResponse = req.body.SAMLResponse;

        if (!samlResponse) {
          throw new Error('No SAMLResponse found in request body');
        }

        // Validate and parse the SAML response
        const profile = await this.samlService.validateResponse(samlResponse);

        // Store user in request
        req.samlUser = profile;

        // Call custom auth handler if provided
        if (this.options.onAuth) {
          const result = await this.options.onAuth(profile, req, res);
          if (result === false) {
            return; // Custom handler took over
          }
        }

        // Store in session if available
        if (req.session && this.options.sessionProperty) {
          (req.session as unknown as SAMLSession)[this.options.sessionProperty] = profile;
        }

        // Redirect to original URL or success redirect
        const session = req.session as unknown as SAMLSession;
        const returnTo = session?.returnTo || this.options.successRedirect;
        if (session?.returnTo) {
          delete session.returnTo;
        }

        res.redirect(returnTo as string);
      } catch (error) {
        this.handleError(error as Error, req, res);
      }
    };
  }

  /**
   * Middleware to protect routes - requires SAML authentication
   */
  public requireAuth(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      // Check if user is in session
      const sessionProperty = this.options.sessionProperty || 'samlUser';
      const session = req.session as unknown as SAMLSession;
      const user = session?.[sessionProperty] as SAMLProfile | undefined;

      if (user) {
        req.samlUser = user;
        return next();
      }

      // Store the original URL and redirect to login
      if (req.session) {
        (req.session as unknown as SAMLSession).returnTo = req.originalUrl || req.url;
      }

      const loginUrl = this.samlService.getLoginUrl();
      res.redirect(loginUrl);
    };
  }

  /**
   * Logout handler
   */
  public logout(): RequestHandler {
    return (req: Request, res: Response) => {
      try {
        const sessionProperty = this.options.sessionProperty || 'samlUser';
        const session = req.session as unknown as SAMLSession;
        const user = session?.[sessionProperty] as SAMLProfile | undefined;

        // Clear session
        if (req.session) {
          req.session.destroy((err) => {
            if (err) {
              console.error('Session destruction error:', err);
            }
          });
        }

        // If we have a user with session index, initiate SLO
        if (user?.nameID && this.options.logoutUrl) {
          const logoutRequest = this.samlService.generateLogoutRequest(
            user.nameID,
            user.sessionIndex
          );

          const params = new URLSearchParams({
            SAMLRequest: logoutRequest.encoded,
          });

          return res.redirect(`${this.options.logoutUrl}?${params.toString()}`);
        }

        // Simple local logout
        res.redirect('/');
      } catch (error) {
        this.handleError(error as Error, req, res);
      }
    };
  }

  /**
   * Metadata endpoint - provides SP metadata to IdP
   */
  public metadata(): RequestHandler {
    return (req: Request, res: Response) => {
      try {
        const metadata = this.generateMetadata();
        res.type('application/xml');
        res.send(metadata);
      } catch (error) {
        this.handleError(error as Error, req, res);
      }
    };
  }

  /**
   * Generates SP metadata XML
   */
  private generateMetadata(): string {
    const cert = this.options.cert
      ?.replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s/g, '');

    return `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="${this.options.issuer}">
  <SPSSODescriptor 
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="${this.options.signRequest ? 'true' : 'false'}"
    WantAssertionsSigned="${this.options.wantAssertionsSigned ? 'true' : 'false'}">
    ${cert ? `
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>` : ''}
    <NameIDFormat>${this.options.nameIdFormat}</NameIDFormat>
    <AssertionConsumerService 
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${this.options.callbackUrl}"
      index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
  }

  /**
   * Handles errors
   */
  private handleError(error: Error, req: Request, res: Response): void {
    console.error('SAML Error:', error);

    if (this.options.onError) {
      return this.options.onError(error, req, res);
    }

    // Default error handling
    if (this.options.failureRedirect) {
      return res.redirect(this.options.failureRedirect);
    }

    res.status(500).json({
      error: 'Authentication failed',
      message: error.message,
    });
  }
}

/**
 * Factory function to create SAML middleware
 */
export function createSAMLMiddleware(options: SAMLMiddlewareOptions): SAMLMiddleware {
  return new SAMLMiddleware(options);
}

