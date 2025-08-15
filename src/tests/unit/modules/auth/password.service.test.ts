import { PasswordService } from '@/modules/auth/services/password.service';
import { prisma } from '@/core/database/prisma.client';
import {
  verifyPassword,
  hashPassword,
  checkPasswordHistory,
  addPasswordToHistory,
} from '@/modules/auth/utils/password.utils';
import { generateResetToken, hashToken } from '@/modules/auth/utils/token.utils';
import { sendPasswordResetEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { sessionService } from '@/modules/auth/services/session.service';
import { logger } from '@/common/utils/logger';
import { UnauthorizedError, ValidationError, NotFoundError } from '@/common/exceptions/app.error';

// Mock all dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    passwordReset: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/utils/password.utils');
jest.mock('@/modules/auth/utils/token.utils');
jest.mock('@/modules/shared/utils/email.utils');
jest.mock('@/modules/shared/services/audit.service');
jest.mock('@/modules/auth/services/session.service');
jest.mock('@/common/utils/logger');

describe('PasswordService', () => {
  let passwordService: PasswordService;

  beforeEach(() => {
    passwordService = new PasswordService();
    jest.clearAllMocks();
  });

  describe('changePassword', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      passwordHash: 'old_hash',
      status: 'ACTIVE',
    };

    it('should successfully change password', async () => {
      // Arrange
      const options = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: false,
        ipAddress: '192.168.1.1',
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      // Mock verifyPassword calls - IMPORTANT: Different returns for each call
      (verifyPassword as jest.Mock)
        .mockResolvedValueOnce(true) // First call: current password is correct
        .mockResolvedValueOnce(false); // Second call: new password is different from current
      (checkPasswordHistory as jest.Mock).mockResolvedValue(true); // true = NOT in history (good)
      (hashPassword as jest.Mock).mockResolvedValue('new_hash');
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({ ...mockUser, passwordHash: 'new_hash' }),
          },
        };
        return callback(mockTx);
      });

      // Act
      await passwordService.changePassword(options);

      // Assert
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: options.userId },
        select: {
          id: true,
          email: true,
          passwordHash: true,
          status: true,
        },
      });
      expect(verifyPassword).toHaveBeenCalledTimes(2);
      expect(verifyPassword).toHaveBeenNthCalledWith(
        1,
        options.currentPassword,
        mockUser.passwordHash,
      );
      expect(verifyPassword).toHaveBeenNthCalledWith(2, options.newPassword, mockUser.passwordHash);
      expect(checkPasswordHistory).toHaveBeenCalledWith(options.userId, options.newPassword);
      expect(hashPassword).toHaveBeenCalledWith(options.newPassword);
    });

    it('should logout all devices when requested', async () => {
      // Arrange
      const options = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: true,
        ipAddress: '192.168.1.1',
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (verifyPassword as jest.Mock).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
      (checkPasswordHistory as jest.Mock).mockResolvedValue(true);
      (hashPassword as jest.Mock).mockResolvedValue('new_hash');
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({ ...mockUser, passwordHash: 'new_hash' }),
          },
        };
        return callback(mockTx);
      });

      // Act
      await passwordService.changePassword(options);

      // Assert
      expect(sessionService.deactivateUserSessions).toHaveBeenCalledWith(
        options.userId,
        expect.anything(),
      );
      expect(sessionService.revokeUserRefreshTokens).toHaveBeenCalledWith(
        options.userId,
        expect.anything(),
      );
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const options = {
        userId: 'non-existent',
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: false,
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      // Act & Assert
      await expect(passwordService.changePassword(options)).rejects.toThrow(UnauthorizedError);
      await expect(passwordService.changePassword(options)).rejects.toThrow('User not found');
    });

    it('should throw error if user is not active', async () => {
      // Arrange
      const inactiveUser = { ...mockUser, status: 'SUSPENDED' };
      const options = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: false,
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(passwordService.changePassword(options)).rejects.toThrow(UnauthorizedError);
      await expect(passwordService.changePassword(options)).rejects.toThrow(
        'Account is not active',
      );
    });

    it('should throw error for incorrect current password', async () => {
      // Arrange
      const options = {
        userId: 'user-123',
        currentPassword: 'WrongPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: false,
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (verifyPassword as jest.Mock).mockResolvedValueOnce(false); // current password is wrong

      // Act & Assert
      await expect(passwordService.changePassword(options)).rejects.toThrow(UnauthorizedError);
      await expect(passwordService.changePassword(options)).rejects.toThrow(
        'Current password is incorrect',
      );
    });

    it('should throw error if new password same as current', async () => {
      // Arrange
      const options = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'OldPass123!', // Same as current
        logoutAllDevices: false,
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      // Use mockImplementation to handle multiple calls correctly
      let callCount = 0;
      (verifyPassword as jest.Mock).mockImplementation(async () => {
        callCount++;
        // First call (current password check) and third call should return true
        // Second call (new vs current check) and fourth call should return true (same password)
        return true; // Both calls return true - passwords match
      });

      // Act & Assert
      await expect(passwordService.changePassword(options)).rejects.toThrow(ValidationError);
      await expect(passwordService.changePassword(options)).rejects.toThrow(
        'New password must be different from current password',
      );
    });

    it('should throw error for password in history', async () => {
      // Arrange
      const options = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'ReusedPass456!',
        logoutAllDevices: false,
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      // Use mockImplementation to handle multiple calls correctly
      let callCount = 0;
      (verifyPassword as jest.Mock).mockImplementation(async (password) => {
        callCount++;
        // Odd calls (1, 3, 5...) check current password - should be valid
        // Even calls (2, 4, 6...) check if new password same as current - should be different
        return callCount % 2 === 1 ? true : false;
      });
      (checkPasswordHistory as jest.Mock).mockResolvedValue(false); // false = IS in history (bad)

      // Act & Assert
      await expect(passwordService.changePassword(options)).rejects.toThrow(ValidationError);
      await expect(passwordService.changePassword(options)).rejects.toThrow(
        /This password has been used recently/,
      );
    });
  });

  describe('forgotPassword', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      status: 'ACTIVE',
      profile: {
        firstName: 'Test',
      },
    };

    it('should send password reset email for valid user', async () => {
      // Arrange
      const options = {
        email: 'test@example.com',
        ipAddress: '192.168.1.1',
      };
      const mockToken = 'reset-token-123';
      const mockHashedToken = 'hashed-token-123';

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.passwordReset.findFirst as jest.Mock).mockResolvedValue(null);
      (generateResetToken as jest.Mock).mockReturnValue(mockToken);
      (hashToken as jest.Mock).mockReturnValue(mockHashedToken);

      // Act
      await passwordService.forgotPassword(options);

      // Assert
      expect(prisma.passwordReset.create).toHaveBeenCalledWith({
        data: {
          userId: mockUser.id,
          email: mockUser.email,
          token: mockHashedToken,
          expiresAt: expect.any(Date),
        },
      });
      expect(sendPasswordResetEmail).toHaveBeenCalledWith(
        { email: mockUser.email, firstName: 'Test' },
        mockToken, // unhashed token sent in email
      );
    });

    it('should not send email for non-existent user', async () => {
      // Arrange
      const options = {
        email: 'nonexistent@example.com',
        ipAddress: '192.168.1.1',
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      // Act
      await passwordService.forgotPassword(options);

      // Assert
      expect(sendPasswordResetEmail).not.toHaveBeenCalled();
      expect(prisma.passwordReset.create).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        {
          email: options.email,
          userExists: false,
          userStatus: undefined,
        },
        'Password reset requested for invalid user',
      );
    });

    it('should not send email for inactive user', async () => {
      // Arrange
      const inactiveUser = { ...mockUser, status: 'SUSPENDED' };
      const options = {
        email: 'test@example.com',
        ipAddress: '192.168.1.1',
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(inactiveUser);

      // Act
      await passwordService.forgotPassword(options);

      // Assert
      expect(sendPasswordResetEmail).not.toHaveBeenCalled();
      expect(prisma.passwordReset.create).not.toHaveBeenCalled();
    });

    it('should not create new token if recent one exists', async () => {
      // Arrange
      const options = {
        email: 'test@example.com',
        ipAddress: '192.168.1.1',
      };
      const existingToken = {
        id: 'token-123',
        expiresAt: new Date(Date.now() + 30 * 60 * 1000),
        createdAt: new Date(Date.now() - 2 * 60 * 1000),
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.passwordReset.findFirst as jest.Mock).mockResolvedValue(existingToken);

      // Act
      await passwordService.forgotPassword(options);

      // Assert
      expect(prisma.passwordReset.create).not.toHaveBeenCalled();
      expect(sendPasswordResetEmail).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const mockResetToken = {
      id: 'reset-123',
      userId: 'user-123',
      token: 'hashed-token',
      usedAt: null,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      user: {
        id: 'user-123',
        email: 'test@example.com',
        status: 'ACTIVE',
        profile: {
          firstName: 'Test',
        },
      },
    };

    it('should successfully reset password with valid token', async () => {
      // Arrange
      const options = {
        token: 'unhashed-token',
        newPassword: 'NewSecurePass789!',
        ipAddress: '192.168.1.1',
      };
      const hashedNewPassword = 'hashed-new-password';

      (hashToken as jest.Mock).mockReturnValue('hashed-token');
      (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(mockResetToken);
      (checkPasswordHistory as jest.Mock).mockResolvedValue(true); // true = NOT in history (good)
      (hashPassword as jest.Mock).mockResolvedValue(hashedNewPassword);
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest
              .fn()
              .mockResolvedValue({ ...mockResetToken.user, passwordHash: hashedNewPassword }),
          },
          passwordReset: {
            update: jest.fn().mockResolvedValue({ ...mockResetToken, usedAt: new Date() }),
          },
        };
        return callback(mockTx);
      });

      // Act
      await passwordService.resetPassword(options);

      // Assert
      expect(hashToken).toHaveBeenCalledWith(options.token);
      expect(prisma.passwordReset.findUnique).toHaveBeenCalledWith({
        where: { token: 'hashed-token' },
        include: { user: { include: { profile: true } } },
      });
      expect(checkPasswordHistory).toHaveBeenCalledWith(mockResetToken.userId, options.newPassword);
      expect(sessionService.deactivateUserSessions).toHaveBeenCalled();
      expect(sessionService.revokeUserRefreshTokens).toHaveBeenCalled();
    });

    it('should throw error for invalid token', async () => {
      // Arrange
      const options = {
        token: 'invalid-token',
        newPassword: 'NewPass456!',
        ipAddress: '192.168.1.1',
      };

      (hashToken as jest.Mock).mockReturnValue('hashed-invalid');
      (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(null);

      // Act & Assert
      await expect(passwordService.resetPassword(options)).rejects.toThrow(NotFoundError);
      await expect(passwordService.resetPassword(options)).rejects.toThrow(
        'Invalid or expired reset token',
      );
    });

    it('should throw error for expired token', async () => {
      // Arrange
      const expiredToken = {
        ...mockResetToken,
        expiresAt: new Date(Date.now() - 60 * 1000),
      };
      const options = {
        token: 'expired-token',
        newPassword: 'NewPass456!',
        ipAddress: '192.168.1.1',
      };

      (hashToken as jest.Mock).mockReturnValue('hashed-token');
      (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(expiredToken);

      // Act & Assert
      await expect(passwordService.resetPassword(options)).rejects.toThrow(ValidationError);
      await expect(passwordService.resetPassword(options)).rejects.toThrow(
        'This reset token has expired',
      );
    });

    it('should throw error for already used token', async () => {
      // Arrange
      const usedToken = {
        ...mockResetToken,
        usedAt: new Date(Date.now() - 10 * 60 * 1000),
      };
      const options = {
        token: 'used-token',
        newPassword: 'NewPass456!',
        ipAddress: '192.168.1.1',
      };

      (hashToken as jest.Mock).mockReturnValue('hashed-token');
      (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(usedToken);

      // Act & Assert
      await expect(passwordService.resetPassword(options)).rejects.toThrow(ValidationError);
      await expect(passwordService.resetPassword(options)).rejects.toThrow(
        'This reset token has already been used',
      );
    });
  });
});
