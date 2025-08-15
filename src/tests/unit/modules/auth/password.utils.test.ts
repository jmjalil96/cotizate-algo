import bcrypt from 'bcrypt';
import {
  hashPassword,
  verifyPassword,
  validatePasswordStrength,
  generateTemporaryPassword,
  checkPasswordHistory,
  addPasswordToHistory,
  calculatePasswordEntropy,
  getPasswordStrength,
} from '@/modules/auth/utils/password.utils';
import { prisma } from '@/core/database/prisma.client';

// Mock dependencies
jest.mock('bcrypt');
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    passwordHistory: {
      findMany: jest.fn(),
      create: jest.fn(),
      deleteMany: jest.fn(),
    },
  },
}));

describe('Password Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'SecurePass123!';
      const hashedPassword = 'hashed_password_123';

      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);

      const result = await hashPassword(password);

      expect(result).toBe(hashedPassword);
      expect(bcrypt.hash).toHaveBeenCalledWith(password, 12); // BCRYPT_ROUNDS default
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'SecurePass123!';
      const hash = 'hashed_password_123';

      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await verifyPassword(password, hash);

      expect(result).toBe(true);
      expect(bcrypt.compare).toHaveBeenCalledWith(password, hash);
    });

    it('should reject incorrect password', async () => {
      const password = 'WrongPass123!';
      const hash = 'hashed_password_123';

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await verifyPassword(password, hash);

      expect(result).toBe(false);
      expect(bcrypt.compare).toHaveBeenCalledWith(password, hash);
    });
  });

  describe('validatePasswordStrength', () => {
    it('should validate strong password', () => {
      const password = 'SecurePass123!';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject password too short', () => {
      const password = 'Pass1!';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters');
    });

    it('should reject password without uppercase', () => {
      const password = 'securepass123!';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter');
    });

    it('should reject password without lowercase', () => {
      const password = 'SECUREPASS123!';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter');
    });

    it('should reject password without number', () => {
      const password = 'SecurePass!';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number');
    });

    it('should reject password without special character', () => {
      const password = 'SecurePass123';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one special character');
    });

    it('should return multiple errors for weak password', () => {
      const password = 'pass';

      const result = validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);
    });
  });

  describe('generateTemporaryPassword', () => {
    it('should generate a 16-character password', () => {
      const password = generateTemporaryPassword();

      expect(password).toHaveLength(16);
    });

    it('should generate unique passwords', () => {
      const password1 = generateTemporaryPassword();
      const password2 = generateTemporaryPassword();

      expect(password1).not.toBe(password2);
    });

    it('should include various character types', () => {
      const password = generateTemporaryPassword();
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';

      for (const char of password) {
        expect(chars).toContain(char);
      }
    });
  });

  describe('checkPasswordHistory', () => {
    it('should return true when password not in history', async () => {
      const userId = 'user-123';
      const newPassword = 'NewPass123!';
      const mockHistory = [{ passwordHash: 'old_hash_1' }, { passwordHash: 'old_hash_2' }];

      (prisma.passwordHistory.findMany as jest.Mock).mockResolvedValue(mockHistory);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await checkPasswordHistory(userId, newPassword);

      expect(result).toBe(true);
      expect(prisma.passwordHistory.findMany).toHaveBeenCalledWith({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: 5,
      });
      expect(bcrypt.compare).toHaveBeenCalledTimes(2);
    });

    it('should return false when password is in history', async () => {
      const userId = 'user-123';
      const newPassword = 'OldPass123!';
      const mockHistory = [{ passwordHash: 'matching_hash' }, { passwordHash: 'old_hash_2' }];

      (prisma.passwordHistory.findMany as jest.Mock).mockResolvedValue(mockHistory);
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true) // First password matches
        .mockResolvedValueOnce(false);

      const result = await checkPasswordHistory(userId, newPassword);

      expect(result).toBe(false);
      expect(bcrypt.compare).toHaveBeenCalledTimes(1); // Stops after first match
    });

    it('should use transaction client when provided', async () => {
      const userId = 'user-123';
      const newPassword = 'NewPass123!';
      const mockTx = {
        passwordHistory: {
          findMany: jest.fn().mockResolvedValue([]),
        },
      };

      const result = await checkPasswordHistory(userId, newPassword, mockTx as any);

      expect(result).toBe(true);
      expect(mockTx.passwordHistory.findMany).toHaveBeenCalled();
      expect(prisma.passwordHistory.findMany).not.toHaveBeenCalled();
    });
  });

  describe('addPasswordToHistory', () => {
    it('should add password to history', async () => {
      const userId = 'user-123';
      const passwordHash = 'hashed_password';
      const mockHistory = [{ id: '1' }, { id: '2' }, { id: '3' }];

      (prisma.passwordHistory.create as jest.Mock).mockResolvedValue({});
      (prisma.passwordHistory.findMany as jest.Mock).mockResolvedValue(mockHistory);

      await addPasswordToHistory(userId, passwordHash);

      expect(prisma.passwordHistory.create).toHaveBeenCalledWith({
        data: {
          userId,
          passwordHash,
        },
      });
      expect(prisma.passwordHistory.findMany).toHaveBeenCalled();
      expect(prisma.passwordHistory.deleteMany).not.toHaveBeenCalled();
    });

    it('should delete old passwords when exceeding limit', async () => {
      const userId = 'user-123';
      const passwordHash = 'hashed_password';
      const mockHistory = [
        { id: '1' },
        { id: '2' },
        { id: '3' },
        { id: '4' },
        { id: '5' },
        { id: '6' }, // Exceeds limit of 5
      ];

      (prisma.passwordHistory.create as jest.Mock).mockResolvedValue({});
      (prisma.passwordHistory.findMany as jest.Mock).mockResolvedValue(mockHistory);
      (prisma.passwordHistory.deleteMany as jest.Mock).mockResolvedValue({});

      await addPasswordToHistory(userId, passwordHash);

      expect(prisma.passwordHistory.deleteMany).toHaveBeenCalledWith({
        where: {
          id: { in: ['6'] }, // Delete the oldest one
        },
      });
    });
  });

  describe('calculatePasswordEntropy', () => {
    it('should calculate entropy for password with all character types', () => {
      const password = 'SecurePass123!';

      const entropy = calculatePasswordEntropy(password);

      // 26 lowercase + 26 uppercase + 10 digits + 32 special = 94 charset
      // log2(94) ≈ 6.55, * 14 chars ≈ 91.7
      expect(entropy).toBeGreaterThan(85);
      expect(entropy).toBeLessThan(95);
    });

    it('should calculate lower entropy for simple password', () => {
      const password = 'password'; // Only lowercase

      const entropy = calculatePasswordEntropy(password);

      // log2(26) ≈ 4.7, * 8 chars ≈ 37.6
      expect(entropy).toBeGreaterThan(35);
      expect(entropy).toBeLessThan(40);
    });

    it('should calculate entropy for numeric password', () => {
      const password = '12345678'; // Only digits

      const entropy = calculatePasswordEntropy(password);

      // log2(10) ≈ 3.32, * 8 chars ≈ 26.6
      expect(entropy).toBeGreaterThan(25);
      expect(entropy).toBeLessThan(30);
    });
  });

  describe('getPasswordStrength', () => {
    it('should rate very strong password', () => {
      const password = 'SuperSecure$Pass123!';

      const result = getPasswordStrength(password);

      expect(result.level).toBe('very-strong');
      expect(result.score).toBeGreaterThan(5);
      expect(result.feedback).toHaveLength(0);
    });

    it('should rate weak password', () => {
      const password = 'weak';

      const result = getPasswordStrength(password);

      expect(result.level).toBe('weak');
      expect(result.score).toBeLessThan(3);
      expect(result.feedback.length).toBeGreaterThan(0);
      expect(result.feedback).toContain('Use at least 8 characters');
    });

    it('should provide feedback for missing requirements', () => {
      const password = 'onlylowercase';

      const result = getPasswordStrength(password);

      expect(result.feedback).toContain('Include uppercase letters');
      expect(result.feedback).toContain('Include numbers');
      expect(result.feedback).toContain('Include special characters');
    });

    it('should rate password based on entropy', () => {
      const weakPassword = 'pass';
      const fairPassword = 'password1';
      const goodPassword = 'Password1';
      const strongPassword = 'Password1!';
      const veryStrongPassword = 'SuperSecure$Pass123!XYZ';

      expect(getPasswordStrength(weakPassword).level).toBe('weak');
      expect(getPasswordStrength(fairPassword).level).toBe('good'); // Has lowercase and numbers
      expect(getPasswordStrength(goodPassword).level).toBe('strong'); // Has uppercase, lowercase, numbers
      expect(getPasswordStrength(strongPassword).level).toBe('very-strong'); // Has all character types
      expect(getPasswordStrength(veryStrongPassword).level).toBe('very-strong');
    });
  });
});
