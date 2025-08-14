import { AuthService } from '@/modules/auth/services/auth.service';
import { prisma } from '@/core/database/prisma.client';
import { sessionService } from '@/modules/auth/services/session.service';
import { generateAccessToken } from '@/modules/auth/utils/jwt.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { NotFoundError } from '@/common/exceptions/app.error';

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

describe('AuthService - Verify Tests', () => {
  let authService: AuthService;
  
  beforeEach(() => {
    authService = new AuthService();
    jest.clearAllMocks();
  });

  describe('verify', () => {
    it('should successfully verify valid token', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-123';
      const ipAddress = '192.168.1.50';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';

      // Mock IDs and tokens
      const mockUserId = 'user-verify-123';
      const mockOrgId = 'org-verify-123';
      const mockSessionId = 'session-123';
      const mockRefreshToken = 'refresh-token-abc123';
      const mockAccessToken = 'jwt.access.token';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-123',
        userId: mockUserId,
        email: 'verified@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        user: {
          id: mockUserId,
          email: 'verified@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'John',
            lastName: 'Doe',
          },
          organizationUsers: [
            {
              id: 'org-user-123',
              userId: mockUserId,
              organizationId: mockOrgId, // This is the field used for audit and token
              roleId: 'role-owner-123',
              organization: { // This is the relation used for the response
                id: mockOrgId,
                name: 'Test Organization',
                slug: 'test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      const mockUpdatedUser = {
        id: mockUserId,
        email: 'verified@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        emailVerifiedAt: new Date(),
      };

      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const mockRefreshTokenObj = {
        token: mockRefreshToken,
        sessionId: mockSessionId,
      };

      // Mock transaction implementation
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            update: jest.fn().mockResolvedValue(mockUpdatedUser),
          },
          emailVerification: {
            delete: jest.fn().mockResolvedValue(mockEmailVerification),
          },
        };

        // Mock service calls inside transaction
        (sessionService.createSession as jest.Mock).mockResolvedValue(mockSession);
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue(mockRefreshTokenObj);
        (auditService.logAction as jest.Mock).mockResolvedValue(undefined);

        const result = await callback(mockTx);
        return result;
      });

      // Mock access token generation (outside transaction)
      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      const result = await authService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Check the response structure
      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        user: {
          id: mockUserId,
          email: 'verified@example.com',
          firstName: 'John',
          lastName: 'Doe',
        },
        organization: {
          id: mockOrgId,
          name: 'Test Organization',
          slug: 'test-organization',
        },
      });

      // Verify email verification lookup
      expect(prisma.emailVerification.findUnique).toHaveBeenCalledWith({
        where: { token: verifyToken },
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

      // Verify transaction was called
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);

      // Verify session creation
      expect(sessionService.createSession).toHaveBeenCalledWith({
        userId: mockUserId,
        ipAddress,
        userAgent,
        tx: expect.anything(),
      });

      // Verify refresh token creation
      expect(sessionService.createRefreshToken).toHaveBeenCalledWith({
        userId: mockUserId,
        sessionId: mockSessionId,
        ipAddress,
        userAgent,
        tx: expect.anything(),
      });

      // Verify audit log creation
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId: mockUserId,
          organizationId: mockOrgId, // Uses organizationId field, not organization.id
          action: 'user.email_verified',
          resource: 'user',
          resourceId: mockUserId,
          details: {
            email: 'verified@example.com',
          },
          ipAddress,
        },
        expect.anything() // tx parameter
      );

      // Verify access token generation with correct organizationId
      expect(generateAccessToken).toHaveBeenCalledWith({
        userId: mockUserId,
        email: 'verified@example.com',
        organizationId: mockOrgId, // Uses organizationId field
        sessionId: mockSessionId,
      });
    });

    it('should throw NotFoundError for invalid token', async () => {
      // Arrange
      const invalidToken = 'invalid-token-does-not-exist';
      const ipAddress = '192.168.1.100';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';

      // Mock email verification lookup to return null (token not found)
      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(null);

      // Act & Assert
      await expect(authService.verify(invalidToken, ipAddress, userAgent))
        .rejects.toThrow('Invalid or expired verification token');

      // Verify email verification lookup was attempted
      expect(prisma.emailVerification.findUnique).toHaveBeenCalledWith({
        where: { token: invalidToken },
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

      // Verify that no transaction was started
      expect(prisma.$transaction).not.toHaveBeenCalled();

      // Verify that no session was created
      expect(sessionService.createSession).not.toHaveBeenCalled();

      // Verify that no refresh token was created
      expect(sessionService.createRefreshToken).not.toHaveBeenCalled();

      // Verify that no access token was generated
      expect(generateAccessToken).not.toHaveBeenCalled();

      // Verify that no audit log was created
      expect(auditService.logAction).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedError for expired token', async () => {
      // Arrange
      const expiredToken = 'expired-verification-token-456';
      const ipAddress = '192.168.1.150';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';
      const mockUserId = 'user-expired-123';

      // Mock email verification with expired token
      const mockExpiredVerification = {
        id: 'verification-expired-123',
        userId: mockUserId,
        email: 'expired@example.com',
        token: expiredToken,
        expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago (expired)
        user: {
          id: mockUserId,
          email: 'expired@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Jane',
            lastName: 'Smith',
          },
          organizationUsers: [
            {
              id: 'org-user-expired',
              userId: mockUserId,
              organizationId: 'org-expired-123',
              roleId: 'role-owner-123',
              organization: {
                id: 'org-expired-123',
                name: 'Expired Org',
                slug: 'expired-org',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockExpiredVerification);

      // Act & Assert
      await expect(authService.verify(expiredToken, ipAddress, userAgent))
        .rejects.toThrow('Verification token has expired');

      // Verify email verification lookup was called
      expect(prisma.emailVerification.findUnique).toHaveBeenCalledWith({
        where: { token: expiredToken },
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

      // Verify that no transaction was started
      expect(prisma.$transaction).not.toHaveBeenCalled();

      // Verify that no session was created
      expect(sessionService.createSession).not.toHaveBeenCalled();

      // Verify that no refresh token was created
      expect(sessionService.createRefreshToken).not.toHaveBeenCalled();

      // Verify that no access token was generated
      expect(generateAccessToken).not.toHaveBeenCalled();

      // Verify that no audit log was created
      expect(auditService.logAction).not.toHaveBeenCalled();
    });

    it('should throw NotFoundError when organization not found', async () => {
      // Arrange
      const validToken = 'valid-token-no-org-456';
      const ipAddress = '192.168.1.200';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';
      const mockUserId = 'user-no-org-123';

      // Mock email verification with user that has no organization
      const mockVerificationWithoutOrg = {
        id: 'verification-no-org-123',
        userId: mockUserId,
        email: 'noorg@example.com',
        token: validToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now (valid)
        user: {
          id: mockUserId,
          email: 'noorg@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'No',
            lastName: 'Organization',
          },
          organizationUsers: [], // Empty array - no organization assigned
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockVerificationWithoutOrg);

      // Act & Assert
      await expect(authService.verify(validToken, ipAddress, userAgent))
        .rejects.toThrow('Organization not found');

      // Verify email verification lookup was called
      expect(prisma.emailVerification.findUnique).toHaveBeenCalledWith({
        where: { token: validToken },
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

      // Verify that no transaction was started
      expect(prisma.$transaction).not.toHaveBeenCalled();

      // Verify that no session was created
      expect(sessionService.createSession).not.toHaveBeenCalled();

      // Verify that no refresh token was created
      expect(sessionService.createRefreshToken).not.toHaveBeenCalled();

      // Verify that no access token was generated
      expect(generateAccessToken).not.toHaveBeenCalled();

      // Verify that no audit log was created
      expect(auditService.logAction).not.toHaveBeenCalled();
    });
  });
});