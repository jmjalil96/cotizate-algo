import { AuthService } from '@/modules/auth/services/auth.service';
import { prisma } from '@/core/database/prisma.client';
import { verifyPassword } from '@/modules/auth/utils/password.utils';
import { generateAccessToken } from '@/modules/auth/utils/jwt.utils';
import { sessionService } from '@/modules/auth/services/session.service';
import { auditService } from '@/modules/shared/services/audit.service';
import { UnauthorizedError, NotFoundError } from '@/common/exceptions/app.error';
import type { LoginInput } from '@/modules/auth/validators/auth.schema';

// Mock all dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/utils/password.utils', () => ({
  verifyPassword: jest.fn(),
}));

jest.mock('@/modules/auth/utils/jwt.utils', () => ({
  generateAccessToken: jest.fn(),
}));

jest.mock('@/modules/auth/services/session.service', () => ({
  sessionService: {
    createSession: jest.fn(),
    createRefreshToken: jest.fn(),
  },
}));

jest.mock('@/modules/shared/services/audit.service', () => ({
  auditService: {
    logAction: jest.fn(),
  },
}));

describe('AuthService - Login Tests', () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
    jest.clearAllMocks();
  });

  describe('login', () => {
    const validLoginData: LoginInput = {
      email: 'test@example.com',
      password: 'SecurePass123!',
    };

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      passwordHash: 'hashed_password',
      status: 'ACTIVE',
      emailVerified: true,
      failedLoginCount: 0,
      lockedUntil: null,
      lastLoginAt: null,
      lastLoginIp: null,
      profile: {
        firstName: 'Test',
        lastName: 'User',
      },
      organizationUsers: [
        {
          organizationId: 'org-123',
          organization: {
            id: 'org-123',
            name: 'Test Org',
            slug: 'test-org',
          },
          role: {
            id: 'role-123',
            name: 'owner',
          },
        },
      ],
    };

    it('should successfully login with valid credentials', async () => {
      // Arrange
      const ipAddress = '192.168.1.1';
      const userAgent = 'Mozilla/5.0';
      const mockSession = { id: 'session-123' };
      const mockRefreshToken = { token: 'refresh-token-123' };
      const mockAccessToken = 'access-token-123';

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({ ...mockUser, lastLoginAt: new Date() }),
          },
        };
        return callback(mockTx);
      });
      (sessionService.createSession as jest.Mock).mockResolvedValue(mockSession);
      (sessionService.createRefreshToken as jest.Mock).mockResolvedValue(mockRefreshToken);
      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      const result = await authService.login(validLoginData, ipAddress, userAgent);

      // Assert
      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken.token,
        user: {
          id: mockUser.id,
          email: mockUser.email,
          firstName: mockUser.profile.firstName,
          lastName: mockUser.profile.lastName,
        },
        organization: {
          id: mockUser.organizationUsers[0].organization.id,
          name: mockUser.organizationUsers[0].organization.name,
          slug: mockUser.organizationUsers[0].organization.slug,
        },
      });

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: validLoginData.email },
        include: {
          profile: true,
          organizationUsers: {
            include: {
              organization: true,
              role: true,
            },
          },
        },
      });

      expect(verifyPassword).toHaveBeenCalledWith(validLoginData.password, mockUser.passwordHash);
      expect(sessionService.createSession).toHaveBeenCalled();
      expect(sessionService.createRefreshToken).toHaveBeenCalled();
      expect(generateAccessToken).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
        organizationId: mockUser.organizationUsers[0].organizationId,
        sessionId: mockSession.id,
      });
    });

    it('should throw error for non-existent user', async () => {
      // Arrange
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);
      await expect(authService.login(validLoginData)).rejects.toThrow('Invalid credentials');

      expect(auditService.logAction).toHaveBeenCalledWith({
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          email: validLoginData.email,
          reason: 'user_not_found',
        },
        ipAddress: undefined,
      });
    });

    it('should throw error for wrong password', async () => {
      // Arrange
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (verifyPassword as jest.Mock).mockResolvedValue(false);
      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        failedLoginCount: 1,
      });

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);
      await expect(authService.login(validLoginData)).rejects.toThrow('Invalid credentials');

      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: {
          failedLoginCount: mockUser.failedLoginCount + 1,
        },
      });

      expect(auditService.logAction).toHaveBeenCalledWith({
        userId: mockUser.id,
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          attempt: 1,
          locked: false,
        },
        ipAddress: undefined,
      });
    });

    it('should lock account after 5 failed attempts', async () => {
      // Arrange
      const userWith4Failures = { ...mockUser, failedLoginCount: 4 };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWith4Failures);
      (verifyPassword as jest.Mock).mockResolvedValue(false);
      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...userWith4Failures,
        failedLoginCount: 5,
        lockedUntil: new Date(Date.now() + 15 * 60 * 1000),
      });

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);

      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: {
          failedLoginCount: 5,
          lockedUntil: expect.any(Date),
        },
      });

      expect(auditService.logAction).toHaveBeenCalledWith({
        userId: mockUser.id,
        action: 'auth.login.locked',
        resource: 'auth',
        details: {
          lockedUntil: expect.any(Date),
        },
        ipAddress: undefined,
      });
    });

    it('should reject login for locked account', async () => {
      // Arrange
      const lockedUser = {
        ...mockUser,
        lockedUntil: new Date(Date.now() + 10 * 60 * 1000), // Locked for 10 more minutes
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(lockedUser);

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);
      await expect(authService.login(validLoginData)).rejects.toThrow(/Account temporarily locked/);

      expect(verifyPassword).not.toHaveBeenCalled();
    });

    it('should reject login for unverified user', async () => {
      // Arrange
      const unverifiedUser = {
        ...mockUser,
        status: 'PENDING',
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(unverifiedUser);

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);
      await expect(authService.login(validLoginData)).rejects.toThrow(
        'Please verify your email before logging in',
      );

      expect(auditService.logAction).toHaveBeenCalledWith({
        userId: unverifiedUser.id,
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          reason: 'account_not_active',
          status: 'PENDING',
        },
        ipAddress: undefined,
      });
    });

    it('should reject login for inactive user', async () => {
      // Arrange
      const inactiveUser = {
        ...mockUser,
        status: 'SUSPENDED',
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(inactiveUser);

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(UnauthorizedError);
      await expect(authService.login(validLoginData)).rejects.toThrow('Account is not active');
    });

    it('should reject login for user without organization', async () => {
      // Arrange
      const userWithoutOrg = {
        ...mockUser,
        organizationUsers: [],
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWithoutOrg);
      (verifyPassword as jest.Mock).mockResolvedValue(true);

      // Act & Assert
      await expect(authService.login(validLoginData)).rejects.toThrow(NotFoundError);
      await expect(authService.login(validLoginData)).rejects.toThrow(
        'No organization associated with this account',
      );
    });

    it('should reset failed login count on successful login', async () => {
      // Arrange
      const userWithFailures = {
        ...mockUser,
        failedLoginCount: 3,
      };
      const ipAddress = '192.168.1.1';
      const mockSession = { id: 'session-123' };
      const mockRefreshToken = { token: 'refresh-token-123' };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWithFailures);
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({
              ...userWithFailures,
              failedLoginCount: 0,
              lockedUntil: null,
              lastLoginAt: new Date(),
              lastLoginIp: ipAddress,
            }),
          },
        };
        return callback(mockTx);
      });
      (sessionService.createSession as jest.Mock).mockResolvedValue(mockSession);
      (sessionService.createRefreshToken as jest.Mock).mockResolvedValue(mockRefreshToken);
      (generateAccessToken as jest.Mock).mockReturnValue('access-token');

      // Act
      await authService.login(validLoginData, ipAddress);

      // Assert
      const txCall = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = { user: { update: jest.fn() } };
      await txCall(mockTx);

      expect(mockTx.user.update).toHaveBeenCalledWith({
        where: { id: userWithFailures.id },
        data: {
          failedLoginCount: 0,
          lockedUntil: null,
          lastLoginAt: expect.any(Date),
          lastLoginIp: ipAddress,
        },
      });
    });
  });
});
