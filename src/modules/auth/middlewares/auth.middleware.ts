/// <reference path="../../../common/types/express.d.ts" />
import { Request, Response, NextFunction } from 'express';
import { UnauthorizedError } from '@/common/exceptions/app.error';
import { extractBearerToken, verifyAccessToken } from '../utils/jwt.utils';
import { asyncHandler } from '@/common/utils/async-handler';
import { sessionService } from '../services/session.service';

/**
 * Mode A: JWT-Only Authentication (Fast)
 * For: Reading data, viewing pages, non-critical operations
 * Validates only the JWT token without checking session
 */
export const authenticate = () => {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    // Extract token from Authorization header
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      throw new UnauthorizedError('No authentication token provided');
    }

    try {
      // Verify and decode the token
      const decoded = verifyAccessToken(token);

      // Set user information on request
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        organizationId: decoded.organizationId,
        sessionId: decoded.sessionId,
      };

      next();
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === 'Token has expired') {
          throw new UnauthorizedError('Authentication token has expired');
        }
        if (error.message === 'Invalid token') {
          throw new UnauthorizedError('Invalid authentication token');
        }
      }
      throw new UnauthorizedError('Authentication failed');
    }
  });
};

/**
 * Mode B: JWT + Session Authentication (Secure)
 * For: Payments, deletes, admin actions, sensitive operations
 * Validates JWT AND checks if session is still active
 */
export const authenticateWithSession = () => {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    // Extract token from Authorization header
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      throw new UnauthorizedError('No authentication token provided');
    }

    try {
      // Step 1: Verify and decode the JWT token
      const decoded = verifyAccessToken(token);

      // Step 2: Check if session ID exists in JWT
      if (!decoded.sessionId) {
        throw new UnauthorizedError('Session validation required for this operation');
      }

      // Step 3: Validate session is still active in database
      try {
        const session = await sessionService.getValidSession(decoded.sessionId);

        // Verify session belongs to the same user (extra security)
        if (session.userId !== decoded.userId) {
          throw new UnauthorizedError('Session mismatch');
        }
      } catch (error) {
        // Session is expired, inactive, or doesn't exist
        throw new UnauthorizedError('Session has been terminated or expired');
      }

      // Set user information on request
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        organizationId: decoded.organizationId,
        sessionId: decoded.sessionId,
      };

      next();
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        throw error;
      }
      if (error instanceof Error) {
        if (error.message === 'Token has expired') {
          throw new UnauthorizedError('Authentication token has expired');
        }
        if (error.message === 'Invalid token') {
          throw new UnauthorizedError('Invalid authentication token');
        }
      }
      throw new UnauthorizedError('Authentication failed');
    }
  });
};

/**
 * Optional authentication middleware
 * Validates token if present but doesn't require it
 */
export const authenticateOptional = () => {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      // No token provided, continue without authentication
      return next();
    }

    try {
      // Verify and decode the token
      const decoded = verifyAccessToken(token);

      // Set user information on request
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        organizationId: decoded.organizationId,
        sessionId: decoded.sessionId,
      };
    } catch (error) {
      // Token is invalid or expired, continue without authentication
      // This is optional auth, so we don't throw an error
    }

    next();
  });
};

/**
 * Alias for backward compatibility
 */
export const requireAuth = authenticate;
export const requireAuthWithSession = authenticateWithSession;
