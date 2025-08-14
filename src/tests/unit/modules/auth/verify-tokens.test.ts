import { AuthService } from '@/modules/auth/services/auth.service';
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

describe('AuthService - Verify Token Tests', () => {
  let authService: AuthService;
  
  beforeEach(() => {
    authService = new AuthService();
    jest.clearAllMocks();
  });

  describe('verify - Token Operations', () => {
    it('should create refresh token', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-refresh';
      const ipAddress = '192.168.1.75';
      const userAgent = 'Mozilla/5.0 Chrome/91.0';

      // Mock IDs and tokens
      const mockUserId = 'user-refresh-123';
      const mockOrgId = 'org-refresh-123';
      const mockSessionId = 'session-refresh-123';
      const mockRefreshToken = 'refresh-token-xyz789';
      const mockAccessToken = 'jwt.access.token.refresh';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-refresh-123',
        userId: mockUserId,
        email: 'refresh-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        user: {
          id: mockUserId,
          email: 'refresh-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Refresh',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-refresh-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
                id: mockOrgId,
                name: 'Refresh Test Organization',
                slug: 'refresh-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      const mockUpdatedUser = {
        id: mockUserId,
        email: 'refresh-test@example.com',
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

      // Assert - Verify refresh token creation
      expect(sessionService.createRefreshToken).toHaveBeenCalledWith({
        userId: mockUserId,
        sessionId: mockSessionId,
        ipAddress,
        userAgent,
        tx: expect.anything(),
      });

      expect(sessionService.createRefreshToken).toHaveBeenCalledTimes(1);

      // Verify the result includes the refresh token
      expect(result.refreshToken).toBe(mockRefreshToken);
    });

    it('should generate valid JWT access token', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-jwt';
      const ipAddress = '192.168.1.85';
      const userAgent = 'Mozilla/5.0 Chrome/92.0';

      // Mock IDs and tokens
      const mockUserId = 'user-jwt-123';
      const mockOrgId = 'org-jwt-123';
      const mockSessionId = 'session-jwt-123';
      const mockRefreshToken = 'refresh-token-jwt-abc';
      const mockAccessToken = 'jwt.access.token.generated';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-jwt-123',
        userId: mockUserId,
        email: 'jwt-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        user: {
          id: mockUserId,
          email: 'jwt-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'JWT',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-jwt-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
                id: mockOrgId,
                name: 'JWT Test Organization',
                slug: 'jwt-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      const mockUpdatedUser = {
        id: mockUserId,
        email: 'jwt-test@example.com',
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

        (sessionService.createSession as jest.Mock).mockResolvedValue(mockSession);
        (sessionService.createRefreshToken as jest.Mock).mockResolvedValue(mockRefreshTokenObj);
        (auditService.logAction as jest.Mock).mockResolvedValue(undefined);

        const result = await callback(mockTx);
        return result;
      });

      // Mock access token generation
      (generateAccessToken as jest.Mock).mockReturnValue(mockAccessToken);

      // Act
      const result = await authService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Verify generateAccessToken was called with correct parameters
      expect(generateAccessToken).toHaveBeenCalledWith({
        userId: mockUserId,
        email: 'jwt-test@example.com',
        organizationId: mockOrgId,
        sessionId: mockSessionId,
      });

      expect(generateAccessToken).toHaveBeenCalledTimes(1);

      // Verify the result includes the generated access token
      expect(result.accessToken).toBe(mockAccessToken);
    });
  });
});