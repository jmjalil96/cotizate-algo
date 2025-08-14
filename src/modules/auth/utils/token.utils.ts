import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

/**
 * Generate a secure random token for email verification
 */
export function generateVerificationToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a secure random token for password reset
 */
export function generateResetToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate an invitation token
 */
export function generateInviteToken(): string {
  return uuidv4();
}

/**
 * Generate a 6-digit OTP code
 */
export function generateOTP(): string {
  const otp = Math.floor(100000 + Math.random() * 900000);
  return otp.toString();
}

/**
 * Hash a token for secure storage
 */
export function hashToken(token: string): string {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

/**
 * Generate a secure random string of specified length
 */
export function generateSecureRandomString(length: number): string {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Generate a URL-safe random token
 */
export function generateUrlSafeToken(): string {
  return crypto
    .randomBytes(32)
    .toString('base64url');
}

/**
 * Generate an API key with prefix
 */
export function generateApiKey(prefix: string = 'sk'): {
  key: string;
  hash: string;
} {
  const randomPart = crypto.randomBytes(32).toString('base64url');
  const key = `${prefix}_${randomPart}`;
  const hash = hashToken(key);
  
  return { key, hash };
}

/**
 * Compare tokens in constant time to prevent timing attacks
 */
export function secureTokenCompare(token1: string, token2: string): boolean {
  if (token1.length !== token2.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(
    Buffer.from(token1),
    Buffer.from(token2)
  );
}

/**
 * Generate a device fingerprint token
 */
export function generateDeviceId(): string {
  return uuidv4();
}

/**
 * Generate a session token
 */
export function generateSessionToken(): string {
  return crypto.randomBytes(48).toString('base64url');
}

/**
 * Generate a CSRF token
 */
export function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate token format (basic validation)
 */
export function isValidTokenFormat(
  token: string,
  type: 'hex' | 'base64' | 'uuid' | 'otp'
): boolean {
  switch (type) {
    case 'hex':
      return /^[a-f0-9]{64}$/i.test(token);
    case 'base64':
      return /^[A-Za-z0-9+/]+=*$/.test(token);
    case 'uuid':
      return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token);
    case 'otp':
      return /^\d{6}$/.test(token);
    default:
      return false;
  }
}