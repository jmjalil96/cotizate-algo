import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  decodeWithoutVerify,
  extractBearerToken,
  generateTokenPair,
  isTokenExpired,
  getTokenExpiryTime,
  signCustomToken,
  verifyCustomToken,
} from '@/modules/auth/utils/jwt.utils';
import { env } from '@/core/config/env';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

jest.mock('@/core/config/env', () => ({
  env: {
    JWT_SECRET: 'test-secret-key',
    JWT_EXPIRES_IN: '15m',
  },
}));

describe('JWT Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (uuidv4 as jest.Mock).mockReturnValue('mock-uuid-123');
  });

  describe('generateAccessToken', () => {
    it('should generate a valid access token', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };

      const token = generateAccessToken(payload);

      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT format

      // Verify the token can be decoded
      const decoded = jwt.verify(token, env.JWT_SECRET as string) as any;
      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.organizationId).toBe(payload.organizationId);
      expect(decoded.sessionId).toBe(payload.sessionId);
      expect(decoded.jti).toBe('mock-uuid-123');
    });

    it('should handle payload without optional fields', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };

      const token = generateAccessToken(payload);
      const decoded = jwt.verify(token, env.JWT_SECRET as string) as any;

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.organizationId).toBeUndefined();
      expect(decoded.sessionId).toBeUndefined();
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate a UUID refresh token', () => {
      const token = generateRefreshToken();

      expect(token).toBe('mock-uuid-123');
      expect(uuidv4).toHaveBeenCalled();
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify and decode a valid token', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };
      const token = jwt.sign(payload, env.JWT_SECRET as string);

      const decoded = verifyAccessToken(token);

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.iat).toBeDefined();
    });

    it('should throw error for expired token', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { expiresIn: '-1h' });

      expect(() => verifyAccessToken(token)).toThrow('Token has expired');
    });

    it('should throw error for invalid token', () => {
      const invalidToken = 'invalid.token.here';

      expect(() => verifyAccessToken(invalidToken)).toThrow('Invalid token');
    });

    it('should throw error for token with wrong secret', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };
      const token = jwt.sign(payload, 'wrong-secret');

      expect(() => verifyAccessToken(token)).toThrow('Invalid token');
    });
  });

  describe('extractBearerToken', () => {
    it('should extract token from valid Bearer header', () => {
      const authHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token';

      const token = extractBearerToken(authHeader);

      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token');
    });

    it('should return null for missing header', () => {
      expect(extractBearerToken(undefined)).toBeNull();
      expect(extractBearerToken('')).toBeNull();
    });

    it('should return null for invalid format', () => {
      expect(extractBearerToken('InvalidFormat')).toBeNull();
      expect(extractBearerToken('Basic token')).toBeNull();
      expect(extractBearerToken('Bearer')).toBeNull();
      expect(extractBearerToken('Bearer token extra')).toBeNull();
    });
  });

  describe('decodeWithoutVerify', () => {
    it('should decode token without verification', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };
      const token = jwt.sign(payload, 'any-secret');

      const decoded = decodeWithoutVerify(token);

      expect(decoded?.userId).toBe(payload.userId);
      expect(decoded?.email).toBe(payload.email);
    });

    it('should return null for invalid token', () => {
      const result = decodeWithoutVerify('invalid-token');
      expect(result).toBeNull();
    });
  });

  describe('generateTokenPair', () => {
    it('should generate both access and refresh tokens', () => {
      const payload = {
        userId: 'user-123',
        email: 'test@example.com',
      };

      const { accessToken, refreshToken } = generateTokenPair(payload);

      expect(typeof accessToken).toBe('string');
      expect(accessToken.split('.')).toHaveLength(3);
      expect(refreshToken).toBe('mock-uuid-123');

      const decoded = jwt.verify(accessToken, env.JWT_SECRET as string) as any;
      expect(decoded.userId).toBe(payload.userId);
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for valid non-expired token', () => {
      const payload = { userId: 'user-123' };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { expiresIn: '1h' });

      expect(isTokenExpired(token)).toBe(false);
    });

    it('should return true for expired token', () => {
      const payload = { userId: 'user-123' };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { expiresIn: '-1h' });

      expect(isTokenExpired(token)).toBe(true);
    });

    it('should return true for invalid token', () => {
      expect(isTokenExpired('invalid-token')).toBe(true);
    });

    it('should return true for token without exp', () => {
      const payload = { userId: 'user-123' };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { noTimestamp: true });

      expect(isTokenExpired(token)).toBe(true);
    });
  });

  describe('getTokenExpiryTime', () => {
    it('should return remaining time for valid token', () => {
      const payload = { userId: 'user-123' };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { expiresIn: '1h' });

      const expiryTime = getTokenExpiryTime(token);

      expect(expiryTime).toBeGreaterThan(3500); // Close to 1 hour in seconds
      expect(expiryTime).toBeLessThanOrEqual(3600);
    });

    it('should return 0 for expired token', () => {
      const payload = { userId: 'user-123' };
      const token = jwt.sign(payload, env.JWT_SECRET as string, { expiresIn: '-1h' });

      expect(getTokenExpiryTime(token)).toBe(0);
    });

    it('should return 0 for invalid token', () => {
      expect(getTokenExpiryTime('invalid-token')).toBe(0);
    });
  });

  describe('signCustomToken', () => {
    it('should sign token with custom expiry', () => {
      const payload = {
        customField: 'value',
        userId: 'user-123',
      };
      const expiresIn = '7d';

      const token = signCustomToken(payload, expiresIn);

      expect(typeof token).toBe('string');
      const decoded = jwt.verify(token, env.JWT_SECRET as string) as any;
      expect(decoded.customField).toBe(payload.customField);
      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.jti).toBe('mock-uuid-123');
    });
  });

  describe('verifyCustomToken', () => {
    it('should verify and decode custom token', () => {
      const payload = {
        customField: 'value',
        userId: 'user-123',
      };
      const token = jwt.sign(payload, env.JWT_SECRET as string);

      const decoded = verifyCustomToken<typeof payload>(token);

      expect(decoded.customField).toBe(payload.customField);
      expect(decoded.userId).toBe(payload.userId);
    });

    it('should throw error for invalid custom token', () => {
      expect(() => verifyCustomToken('invalid-token')).toThrow();
    });
  });
});
