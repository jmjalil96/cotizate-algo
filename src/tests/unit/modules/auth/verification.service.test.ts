import { VerificationService } from '@/modules/auth/services/verification.service';
import { prisma } from '@/core/database/prisma.client';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { generateVerificationToken } from '@/modules/auth/utils/token.utils';
import { generateAccessToken } from '@/modules/auth/utils/jwt.utils';
import { sendVerificationEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { sessionService } from '@/modules/auth/services/session.service';
import { logger } from '@/common/utils/logger';

// Mock dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    emailVerification: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      delete: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/utils/token.utils', () => ({
  generateVerificationToken: jest.fn(),
}));

jest.mock('@/modules/auth/utils/jwt.utils', () => ({
  generateAccessToken: jest.fn(),
}));

jest.mock('@/modules/shared/utils/email.utils', () => ({
  sendVerificationEmail: jest.fn(),
}));

jest.mock('@/modules/shared/services/audit.service', () => ({
  auditService: {
    logAction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/services/session.service', () => ({
  sessionService: {
    createSession: jest.fn(),
    createRefreshToken: jest.fn(),
  },
}));

jest.mock('@/common/utils/logger', () => ({
  logger: {
    warn: jest.fn(),
    info: jest.fn(),
  },
}));

describe('VerificationService', () => {
  let verificationService: VerificationService;

  beforeEach(() => {
    verificationService = new VerificationService();
    jest.clearAllMocks();
  });

  describe('resendVerification', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      status: 'PENDING',
      emailVerified: false,
      profile: {
        firstName: 'Test',
        lastName: 'User',
      },
    };

    it('should resend verification email for valid pending user', async () => {
      const mockToken = 'verification-token-123';

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.emailVerification.findFirst as jest.Mock).mockResolvedValue(null);
      (generateVerificationToken as jest.Mock).mockReturnValue(mockToken);
      (prisma.emailVerification.create as jest.Mock).mockResolvedValue({});

      await verificationService.resendVerification('test@example.com', '192.168.1.1');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
        include: { profile: true },
      });
      expect(prisma.emailVerification.create).toHaveBeenCalledWith({
        data: {
          userId: mockUser.id,
          email: mockUser.email,
          token: mockToken,
          expiresAt: expect.any(Date),
        },
      });
      expect(sendVerificationEmail).toHaveBeenCalledWith(
        {
          email: mockUser.email,
          firstName: 'Test',
        },
        mockToken,
      );
      expect(auditService.logAction).toHaveBeenCalledWith({
        userId: mockUser.id,
        action: 'auth.verification.resend.success',
        resource: 'auth',
        details: { email: 'test@example.com' },
        ipAddress: '192.168.1.1',
      });
    });

    it('should not send email for non-existent user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await verificationService.resendVerification('nonexistent@example.com', '192.168.1.1');

      expect(sendVerificationEmail).not.toHaveBeenCalled();
      expect(prisma.emailVerification.create).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        {
          email: 'nonexistent@example.com',
          userExists: false,
          userStatus: undefined,
        },
        'Resend verification requested for invalid user',
      );
    });

    it('should not send email for already verified user', async () => {
      const verifiedUser = { ...mockUser, status: 'ACTIVE', emailVerified: true };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(verifiedUser);

      await verificationService.resendVerification('test@example.com', '192.168.1.1');

      expect(sendVerificationEmail).not.toHaveBeenCalled();
      expect(prisma.emailVerification.create).not.toHaveBeenCalled();
      expect(auditService.logAction).toHaveBeenCalledWith({
        userId: verifiedUser.id,
        action: 'auth.verification.resend.failed',
        resource: 'auth',
        details: { reason: 'already_verified' },
        ipAddress: '192.168.1.1',
      });
    });

    it('should not create new token if recent one exists', async () => {
      const existingToken = {
        id: 'token-123',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdAt: new Date(Date.now() - 2 * 60 * 1000),
      };

      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.emailVerification.findFirst as jest.Mock).mockResolvedValue(existingToken);

      await verificationService.resendVerification('test@example.com', '192.168.1.1');

      expect(prisma.emailVerification.create).not.toHaveBeenCalled();
      expect(sendVerificationEmail).not.toHaveBeenCalled();
      expect(logger.info).toHaveBeenCalledWith(
        {
          userId: mockUser.id,
          email: 'test@example.com',
        },
        'Recent verification token already exists, skipping',
      );
    });
  });

  describe('verify', () => {
    const mockVerification = {
      id: 'verification-123',
      token: 'token-123',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      user: {
        id: 'user-123',
        email: 'test@example.com',
        status: 'PENDING',
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
          },
        ],
      },
    };

    it('should successfully verify email and create session', async () => {
      const mockSession = { id: 'session-123' };
      const mockRefreshToken = { token: 'refresh-token-123' };
      const mockAccessToken = 'access-token-123';

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockVerification);
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({
              ...mockVerification.user,
              status: 'ACTIVE',
              emailVerified: true,
            }),
          },
          emailVerification: {
            delete: jest.fn(),
          },
        };

        (sessionService.createSession as jest.Mock).mockResolvedValue(mockSession);
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue(mockRefreshToken);

        return callback(mockTx);
      });
      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      const result = await verificationService.verify('token-123', '192.168.1.1', 'Mozilla/5.0');

      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken.token,
        user: {
          id: mockVerification.user.id,
          email: mockVerification.user.email,
          firstName: 'Test',
          lastName: 'User',
        },
        organization: {
          id: 'org-123',
          name: 'Test Org',
          slug: 'test-org',
        },
      });

      expect(prisma.emailVerification.findUnique).toHaveBeenCalledWith({
        where: { token: 'token-123' },
        include: {
          user: {
            include: {
              profile: true,
              organizationUsers: {
                include: {
                  organization: true,
                },
              },
            },
          },
        },
      });
      expect(sessionService.createSession).toHaveBeenCalledWith({
        userId: mockVerification.user.id,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        tx: expect.anything(),
      });
      expect(sessionService.createRefreshToken).toHaveBeenCalledWith({
        userId: mockVerification.user.id,
        sessionId: mockSession.id,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        tx: expect.anything(),
      });
      expect(generateAccessToken).toHaveBeenCalledWith({
        userId: mockVerification.user.id,
        email: mockVerification.user.email,
        organizationId: 'org-123',
        sessionId: mockSession.id,
      });
    });

    it('should throw error for invalid token', async () => {
      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(verificationService.verify('invalid-token')).rejects.toThrow(NotFoundError);
      await expect(verificationService.verify('invalid-token')).rejects.toThrow(
        'Invalid or expired verification token',
      );
    });

    it('should throw error for expired token', async () => {
      const expiredVerification = {
        ...mockVerification,
        expiresAt: new Date(Date.now() - 60 * 1000),
      };
      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(expiredVerification);

      await expect(verificationService.verify('token-123')).rejects.toThrow(UnauthorizedError);
      await expect(verificationService.verify('token-123')).rejects.toThrow(
        'Verification token has expired',
      );
    });

    it('should throw error for user without organization', async () => {
      const verificationNoOrg = {
        ...mockVerification,
        user: {
          ...mockVerification.user,
          organizationUsers: [],
        },
      };
      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(verificationNoOrg);

      await expect(verificationService.verify('token-123')).rejects.toThrow(NotFoundError);
      await expect(verificationService.verify('token-123')).rejects.toThrow(
        'Organization not found',
      );
    });
  });
});
