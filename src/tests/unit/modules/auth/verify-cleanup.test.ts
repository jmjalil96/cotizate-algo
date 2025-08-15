import { VerificationService } from '@/modules/auth/services/verification.service';
import { prisma } from '@/core/database/prisma.client';
import { sessionService } from '@/modules/auth/services/session.service';
import { generateAccessToken } from '@/modules/auth/utils/jwt.utils';
import { auditService } from '@/modules/shared/services/audit.service';

// Mock all dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    emailVerification: {
      findUnique: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/services/session.service', () => ({
  sessionService: {
    createSession: jest.fn(),
    createRefreshToken: jest.fn(),
  },
}));

jest.mock('@/modules/auth/utils/jwt.utils', () => ({
  generateAccessToken: jest.fn(),
}));

jest.mock('@/modules/shared/services/audit.service', () => ({
  auditService: {
    logAction: jest.fn(),
  },
}));

describe('VerificationService - Verify Cleanup Tests', () => {
  let verificationService: VerificationService;

  beforeEach(() => {
    verificationService = new VerificationService();
    jest.clearAllMocks();
  });

  describe('verify - Cleanup and Audit', () => {
    it('should delete verification token after use', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-delete';
      const ipAddress = '192.168.1.65';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';
      const mockVerificationId = 'verification-delete-123';

      // Mock IDs and tokens
      const mockUserId = 'user-delete-123';
      const mockOrgId = 'org-delete-123';
      const mockSessionId = 'session-delete-123';
      const mockRefreshToken = 'refresh-token-delete-abc';
      const mockAccessToken = 'jwt.access.token.delete';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: mockVerificationId,
        userId: mockUserId,
        email: 'delete-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        user: {
          id: mockUserId,
          email: 'delete-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Delete',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-delete-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
                id: mockOrgId,
                name: 'Delete Test Organization',
                slug: 'delete-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      let mockTx: any;
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({
              id: mockUserId,
              email: 'delete-test@example.com',
              status: 'ACTIVE',
              emailVerified: true,
              emailVerifiedAt: new Date(),
            }),
          },
          emailVerification: {
            delete: jest.fn().mockResolvedValue(mockEmailVerification),
          },
        };

        (sessionService.createSession as jest.Mock).mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue({
          token: mockRefreshToken,
          sessionId: mockSessionId,
        });
        (auditService.logAction as jest.Mock).mockResolvedValue(undefined);

        const result = await callback(mockTx);
        return result;
      });

      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      await verificationService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Verify token deletion
      expect(mockTx.emailVerification.delete).toHaveBeenCalledWith({
        where: { id: mockVerificationId },
      });
      expect(mockTx.emailVerification.delete).toHaveBeenCalledTimes(1);
    });

    it('should create audit log for email_verified', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-audit';
      const ipAddress = '192.168.1.95';
      const userAgent = 'Mozilla/5.0 Chrome/93.0';

      // Mock IDs
      const mockUserId = 'user-audit-123';
      const mockOrgId = 'org-audit-123';
      const mockSessionId = 'session-audit-123';
      const mockRefreshToken = 'refresh-token-audit-xyz';
      const mockAccessToken = 'jwt.access.token.audit';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-audit-123',
        userId: mockUserId,
        email: 'audit-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        user: {
          id: mockUserId,
          email: 'audit-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Audit',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-audit-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
                id: mockOrgId,
                name: 'Audit Test Organization',
                slug: 'audit-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      let mockTx: any;
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({
              id: mockUserId,
              email: 'audit-test@example.com',
              status: 'ACTIVE',
              emailVerified: true,
              emailVerifiedAt: new Date(),
            }),
          },
          emailVerification: {
            delete: jest.fn().mockResolvedValue(mockEmailVerification),
          },
        };

        (sessionService.createSession as jest.Mock).mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue({
          token: mockRefreshToken,
          sessionId: mockSessionId,
        });
        (auditService.logAction as jest.Mock).mockResolvedValue(undefined);

        const result = await callback(mockTx);
        return result;
      });

      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      await verificationService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Verify audit log creation
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          organizationId: mockOrgId,
          action: 'user.email_verified',
          resource: 'user',
          resourceId: mockUserId,
          details: {
            email: 'audit-test@example.com',
          },
          ipAddress,
        },
        mockTx,
      );
      expect(auditService.logAction).toHaveBeenCalledTimes(1);
    });

    it('should return user and organization info', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-info';
      const ipAddress = '192.168.1.105';
      const userAgent = 'Mozilla/5.0 Chrome/94.0';

      // Mock IDs and tokens
      const mockUserId = 'user-info-123';
      const mockOrgId = 'org-info-123';
      const mockSessionId = 'session-info-123';
      const mockRefreshToken = 'refresh-token-info-def';
      const mockAccessToken = 'jwt.access.token.info';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-info-123',
        userId: mockUserId,
        email: 'info-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        user: {
          id: mockUserId,
          email: 'info-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Info',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-info-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
                id: mockOrgId,
                name: 'Info Test Organization',
                slug: 'info-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue({
              id: mockUserId,
              email: 'info-test@example.com',
              status: 'ACTIVE',
              emailVerified: true,
              emailVerifiedAt: new Date(),
            }),
          },
          emailVerification: {
            delete: jest.fn().mockResolvedValue(mockEmailVerification),
          },
        };

        (sessionService.createSession as jest.Mock).mockResolvedValue({
          id: mockSessionId,
          userId: mockUserId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue({
          token: mockRefreshToken,
          sessionId: mockSessionId,
        });
        (auditService.logAction as jest.Mock).mockResolvedValue(undefined);

        const result = await callback(mockTx);
        return result;
      });

      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      const result = await verificationService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Verify complete response structure
      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        user: {
          id: mockUserId,
          email: 'info-test@example.com',
          firstName: 'Info',
          lastName: 'Test',
        },
        organization: {
          id: mockOrgId,
          name: 'Info Test Organization',
          slug: 'info-test-organization',
        },
      });

      // Verify user info is correctly mapped from profile
      expect(result.user.firstName).toBe('Info');
      expect(result.user.lastName).toBe('Test');

      // Verify organization info is correctly mapped
      expect(result.organization.name).toBe('Info Test Organization');
      expect(result.organization.slug).toBe('info-test-organization');
    });
  });
});
