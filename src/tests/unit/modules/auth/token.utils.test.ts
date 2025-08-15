import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  generateVerificationToken,
  generateResetToken,
  generateInviteToken,
  generateOTP,
  hashToken,
  generateSecureRandomString,
  generateUrlSafeToken,
  generateApiKey,
  secureTokenCompare,
  generateDeviceId,
  generateSessionToken,
  generateCSRFToken,
  isValidTokenFormat,
} from '@/modules/auth/utils/token.utils';

// Mock dependencies
jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

// Partially mock crypto to allow some real functionality
const mockRandomBytes = jest.spyOn(crypto, 'randomBytes');

describe('Token Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (uuidv4 as jest.Mock).mockReturnValue('mock-uuid-123');
    // Reset the mock to use real implementation by default
    mockRandomBytes.mockRestore();
    jest.spyOn(crypto, 'randomBytes');
  });

  describe('generateVerificationToken', () => {
    it('should generate a 64-character hex token', () => {
      const token = generateVerificationToken();

      expect(token).toHaveLength(64);
      expect(token).toMatch(/^[a-f0-9]{64}$/i);
    });

    it('should generate unique tokens', () => {
      const token1 = generateVerificationToken();
      const token2 = generateVerificationToken();

      expect(token1).not.toBe(token2);
    });
  });

  describe('generateResetToken', () => {
    it('should generate a 64-character hex token', () => {
      const token = generateResetToken();

      expect(token).toHaveLength(64);
      expect(token).toMatch(/^[a-f0-9]{64}$/i);
    });

    it('should generate unique tokens', () => {
      const token1 = generateResetToken();
      const token2 = generateResetToken();

      expect(token1).not.toBe(token2);
    });
  });

  describe('generateInviteToken', () => {
    it('should generate a UUID token', () => {
      const token = generateInviteToken();

      expect(token).toBe('mock-uuid-123');
      expect(uuidv4).toHaveBeenCalled();
    });
  });

  describe('generateOTP', () => {
    it('should generate a 6-digit OTP', () => {
      const otp = generateOTP();

      expect(otp).toHaveLength(6);
      expect(otp).toMatch(/^\d{6}$/);
    });

    it('should generate OTP within valid range', () => {
      for (let i = 0; i < 10; i++) {
        const otp = generateOTP();
        const otpNumber = parseInt(otp);
        expect(otpNumber).toBeGreaterThanOrEqual(100000);
        expect(otpNumber).toBeLessThanOrEqual(999999);
      }
    });
  });

  describe('hashToken', () => {
    it('should hash a token consistently', () => {
      const token = 'test-token-123';

      const hash1 = hashToken(token);
      const hash2 = hashToken(token);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 produces 64 hex characters
    });

    it('should produce different hashes for different tokens', () => {
      const hash1 = hashToken('token1');
      const hash2 = hashToken('token2');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('generateSecureRandomString', () => {
    it('should generate string of specified length', () => {
      const lengths = [10, 20, 30, 40];

      lengths.forEach((length) => {
        const str = generateSecureRandomString(length);
        expect(str).toHaveLength(length);
      });
    });

    it('should generate hex string', () => {
      const str = generateSecureRandomString(20);

      expect(str).toMatch(/^[a-f0-9]+$/i);
    });
  });

  describe('generateUrlSafeToken', () => {
    it('should generate a URL-safe base64 token', () => {
      const token = generateUrlSafeToken();

      expect(typeof token).toBe('string');
      // URL-safe base64 uses - and _ instead of + and /
      expect(token).not.toContain('+');
      expect(token).not.toContain('/');
      expect(token).not.toContain('='); // No padding in base64url
    });
  });

  describe('generateApiKey', () => {
    it('should generate API key with default prefix', () => {
      const { key, hash } = generateApiKey();

      expect(key).toMatch(/^sk_[A-Za-z0-9_-]+$/);
      expect(hash).toHaveLength(64);
    });

    it('should generate API key with custom prefix', () => {
      const { key, hash } = generateApiKey('test');

      expect(key).toMatch(/^test_[A-Za-z0-9_-]+$/);
      expect(hash).toHaveLength(64);
    });

    it('should hash the key correctly', () => {
      const { key, hash } = generateApiKey();
      const expectedHash = hashToken(key);

      expect(hash).toBe(expectedHash);
    });
  });

  describe('secureTokenCompare', () => {
    it('should return true for identical tokens', () => {
      const token = 'test-token-123';

      expect(secureTokenCompare(token, token)).toBe(true);
    });

    it('should return false for different tokens', () => {
      expect(secureTokenCompare('token1', 'token2')).toBe(false);
    });

    it('should return false for different length tokens', () => {
      expect(secureTokenCompare('short', 'longer-token')).toBe(false);
    });

    it('should use timing-safe comparison', () => {
      const spy = jest.spyOn(crypto, 'timingSafeEqual');
      const token = 'test-token';

      secureTokenCompare(token, token);

      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('generateDeviceId', () => {
    it('should generate a UUID device ID', () => {
      const deviceId = generateDeviceId();

      expect(deviceId).toBe('mock-uuid-123');
      expect(uuidv4).toHaveBeenCalled();
    });
  });

  describe('generateSessionToken', () => {
    it('should generate a base64url session token', () => {
      const token = generateSessionToken();

      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
      // URL-safe base64
      expect(token).not.toContain('+');
      expect(token).not.toContain('/');
    });
  });

  describe('generateCSRFToken', () => {
    it('should generate a 64-character hex CSRF token', () => {
      const token = generateCSRFToken();

      expect(token).toHaveLength(64);
      expect(token).toMatch(/^[a-f0-9]{64}$/i);
    });
  });

  describe('isValidTokenFormat', () => {
    describe('hex format', () => {
      it('should validate valid hex token', () => {
        const validHex = 'a'.repeat(64);
        expect(isValidTokenFormat(validHex, 'hex')).toBe(true);
      });

      it('should reject invalid hex token', () => {
        expect(isValidTokenFormat('not-hex', 'hex')).toBe(false);
        expect(isValidTokenFormat('a'.repeat(63), 'hex')).toBe(false); // Wrong length
      });
    });

    describe('base64 format', () => {
      it('should validate valid base64 token', () => {
        expect(isValidTokenFormat('dGVzdA==', 'base64')).toBe(true);
        expect(isValidTokenFormat('VGVzdDEyMw==', 'base64')).toBe(true);
      });

      it('should reject invalid base64 token', () => {
        expect(isValidTokenFormat('not@base64!', 'base64')).toBe(false);
      });
    });

    describe('uuid format', () => {
      it('should validate valid UUID', () => {
        const validUUID = '550e8400-e29b-41d4-a716-446655440000';
        expect(isValidTokenFormat(validUUID, 'uuid')).toBe(true);
      });

      it('should reject invalid UUID', () => {
        expect(isValidTokenFormat('not-a-uuid', 'uuid')).toBe(false);
        expect(isValidTokenFormat('550e8400-e29b-11d4-a716-446655440000', 'uuid')).toBe(false); // Wrong version
      });
    });

    describe('otp format', () => {
      it('should validate valid 6-digit OTP', () => {
        expect(isValidTokenFormat('123456', 'otp')).toBe(true);
        expect(isValidTokenFormat('000000', 'otp')).toBe(true);
        expect(isValidTokenFormat('999999', 'otp')).toBe(true);
      });

      it('should reject invalid OTP', () => {
        expect(isValidTokenFormat('12345', 'otp')).toBe(false); // Too short
        expect(isValidTokenFormat('1234567', 'otp')).toBe(false); // Too long
        expect(isValidTokenFormat('12345a', 'otp')).toBe(false); // Contains letter
      });
    });

    it('should return false for unknown type', () => {
      expect(isValidTokenFormat('any-token', 'unknown' as any)).toBe(false);
    });
  });
});
