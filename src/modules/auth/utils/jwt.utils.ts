import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { env } from '@/core/config/env';

export interface AccessTokenPayload {
  userId: string;
  email: string;
  organizationId?: string;
  sessionId?: string;
}

export interface DecodedToken extends AccessTokenPayload {
  iat: number;
  exp: number;
  jti?: string;
}

/**
 * Generate an access token (short-lived)
 */
export function generateAccessToken(payload: AccessTokenPayload): string {
  const options: SignOptions = {
    expiresIn: (env.JWT_EXPIRES_IN || '15m') as any,
    jwtid: uuidv4(),
  };
  
  return jwt.sign(payload, env.JWT_SECRET as string, options);
}

/**
 * Generate a refresh token (long-lived, stored in DB)
 */
export function generateRefreshToken(): string {
  return uuidv4();
}

/**
 * Verify and decode an access token
 */
export function verifyAccessToken(token: string): DecodedToken {
  try {
    return jwt.verify(token, env.JWT_SECRET as string) as DecodedToken;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token has expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    }
    throw error;
  }
}

/**
 * Decode token without verification (for debugging)
 */
export function decodeWithoutVerify(token: string): DecodedToken | null {
  const decoded = jwt.decode(token);
  return decoded as DecodedToken | null;
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(authHeader?: string): string | null {
  if (!authHeader) return null;
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }
  
  return parts[1];
}

/**
 * Generate token pair (access + refresh)
 */
export function generateTokenPair(payload: AccessTokenPayload): {
  accessToken: string;
  refreshToken: string;
} {
  return {
    accessToken: generateAccessToken(payload),
    refreshToken: generateRefreshToken(),
  };
}

/**
 * Check if token is expired
 */
export function isTokenExpired(token: string): boolean {
  try {
    const decoded = decodeWithoutVerify(token);
    if (!decoded || !decoded.exp) return true;
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch {
    return true;
  }
}

/**
 * Get time until token expiry in seconds
 */
export function getTokenExpiryTime(token: string): number {
  const decoded = decodeWithoutVerify(token);
  if (!decoded || !decoded.exp) return 0;
  
  const currentTime = Math.floor(Date.now() / 1000);
  return Math.max(0, decoded.exp - currentTime);
}

/**
 * Sign a payload with custom expiry
 */
export function signCustomToken(
  payload: Record<string, any>,
  expiresIn: string
): string {
  const options: SignOptions = {
    expiresIn: expiresIn as any,
    jwtid: uuidv4(),
  };
  
  return jwt.sign(payload, env.JWT_SECRET as string, options);
}

/**
 * Verify a custom token
 */
export function verifyCustomToken<T = any>(token: string): T {
  return jwt.verify(token, env.JWT_SECRET as string) as T;
}