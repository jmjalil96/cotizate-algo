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

describe('AuthService - Verify Behavior Tests', () => {
  let authService: AuthService;
  let mockTx: any;
  
  beforeEach(() => {
    authService = new AuthService();
    jest.clearAllMocks();
    
    // Set up mock transaction object
    mockTx = {
      user: {
        update: jest.fn(),
      },
      emailVerification: {
        delete: jest.fn(),
      },
    };
  });

  describe('verify - User Status Update Behavior', () => {
    it('should update user status to ACTIVE', async () => {
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
              organizationId: mockOrgId,
              roleId: 'role-owner-123',
              organization: {
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
        emailVerifiedAt: expect.any(Date),
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
        mockTx.user.update.mockResolvedValue(mockUpdatedUser);
        mockTx.emailVerification.delete.mockResolvedValue(mockEmailVerification);

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
      await authService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Focus on user.update call
      expect(mockTx.user.update).toHaveBeenCalledWith({
        where: { id: mockUserId },
        data: {
          status: 'ACTIVE',
          emailVerified: true,
          emailVerifiedAt: expect.any(Date),
        },
      });

      // Verify that user.update was called exactly once
      expect(mockTx.user.update).toHaveBeenCalledTimes(1);

      // Verify transaction was called
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it('should set emailVerified to true with timestamp', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-456';
      const ipAddress = '192.168.1.75';
      const userAgent = 'Mozilla/5.0 Firefox/95.0';

      // Mock IDs and tokens
      const mockUserId = 'user-email-verify-456';
      const mockOrgId = 'org-email-verify-456';
      const mockSessionId = 'session-456';
      const mockRefreshToken = 'refresh-token-def456';
      const mockAccessToken = 'jwt.access.token.456';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-456',
        userId: mockUserId,
        email: 'email-verify@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        user: {
          id: mockUserId,
          email: 'email-verify@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Jane',
            lastName: 'Smith',
          },
          organizationUsers: [
            {
              id: 'org-user-456',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-456',
              organization: {
                id: mockOrgId,
                name: 'Email Test Organization',
                slug: 'email-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Mock transaction operations
      const mockUpdatedUser = {
        id: mockUserId,
        email: 'email-verify@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        emailVerifiedAt: expect.any(Date),
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

      // Capture the timestamp when test starts
      const testStartTime = new Date();

      // Mock transaction implementation
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        mockTx.user.update.mockResolvedValue(mockUpdatedUser);
        mockTx.emailVerification.delete.mockResolvedValue(mockEmailVerification);

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
      await authService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Focus on emailVerified and emailVerifiedAt fields
      expect(mockTx.user.update).toHaveBeenCalledWith({
        where: { id: mockUserId },
        data: {
          status: 'ACTIVE',
          emailVerified: true,
          emailVerifiedAt: expect.any(Date),
        },
      });

      // Verify emailVerified is set to true
      const updateCall = mockTx.user.update.mock.calls[0][0];
      expect(updateCall.data.emailVerified).toBe(true);

      // Verify emailVerifiedAt is a Date instance
      expect(updateCall.data.emailVerifiedAt).toBeInstanceOf(Date);

      // Verify the timestamp is recent (within last 5 seconds)
      const testEndTime = new Date();
      const emailVerifiedAt = updateCall.data.emailVerifiedAt;
      expect(emailVerifiedAt.getTime()).toBeGreaterThanOrEqual(testStartTime.getTime());
      expect(emailVerifiedAt.getTime()).toBeLessThanOrEqual(testEndTime.getTime());

      // Verify that user.update was called exactly once
      expect(mockTx.user.update).toHaveBeenCalledTimes(1);

      // Verify transaction was called
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it('should create session with correct expiry', async () => {
      // Arrange
      const verifyToken = 'valid-verification-token-789';
      const ipAddress = '192.168.1.100';
      const userAgent = 'Mozilla/5.0 Safari/17.0';

      // Mock IDs and tokens
      const mockUserId = 'user-session-789';
      const mockOrgId = 'org-session-789';
      const mockSessionId = 'session-789';
      const mockRefreshToken = 'refresh-token-ghi789';
      const mockAccessToken = 'jwt.access.token.789';

      // Mock email verification with complete user data
      const mockEmailVerification = {
        id: 'verification-789',
        userId: mockUserId,
        email: 'session-test@example.com',
        token: verifyToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        user: {
          id: mockUserId,
          email: 'session-test@example.com',
          status: 'PENDING',
          emailVerified: false,
          profile: {
            firstName: 'Session',
            lastName: 'Test',
          },
          organizationUsers: [
            {
              id: 'org-user-789',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: 'role-owner-789',
              organization: {
                id: mockOrgId,
                name: 'Session Test Organization',
                slug: 'session-test-organization',
              },
            },
          ],
        },
      };

      (prisma.emailVerification.findUnique as jest.Mock).mockResolvedValue(mockEmailVerification);

      // Capture the timestamp when test starts for expiry validation
      const testStartTime = new Date();

      // Mock transaction operations
      const mockUpdatedUser = {
        id: mockUserId,
        email: 'session-test@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        emailVerifiedAt: expect.any(Date),
      };

      // Create session with 24-hour expiry (24 * 60 * 60 * 1000 = 86400000 ms)
      const expectedExpiryTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
      const mockSession = {
        id: mockSessionId,
        userId: mockUserId,
        token: 'session-token-789',
        ipAddress,
        userAgent,
        expiresAt: expectedExpiryTime,
      };

      const mockRefreshTokenObj = {
        token: mockRefreshToken,
        sessionId: mockSessionId,
      };

      // Mock transaction implementation
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        mockTx.user.update.mockResolvedValue(mockUpdatedUser);
        mockTx.emailVerification.delete.mockResolvedValue(mockEmailVerification);

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
      await authService.verify(verifyToken, ipAddress, userAgent);

      // Assert - Verify sessionService.createSession was called with correct parameters
      expect(sessionService.createSession).toHaveBeenCalledWith({
        userId: mockUserId,
        ipAddress,
        userAgent,
        tx: mockTx,
      });

      // Verify sessionService.createSession was called exactly once
      expect(sessionService.createSession).toHaveBeenCalledTimes(1);

      // Verify the session has an expiry time approximately 24 hours from now
      const sessionExpiryTime = mockSession.expiresAt;
      const testEndTime = new Date();
      
      // Calculate expected 24-hour window (86400000 ms = 24 hours)
      const expectedMinExpiry = new Date(testStartTime.getTime() + 24 * 60 * 60 * 1000 - 5000); // -5s tolerance
      const expectedMaxExpiry = new Date(testEndTime.getTime() + 24 * 60 * 60 * 1000 + 5000); // +5s tolerance

      expect(sessionExpiryTime).toBeInstanceOf(Date);
      expect(sessionExpiryTime.getTime()).toBeGreaterThanOrEqual(expectedMinExpiry.getTime());
      expect(sessionExpiryTime.getTime()).toBeLessThanOrEqual(expectedMaxExpiry.getTime());

      // Verify the expiry is approximately 24 hours from the test start time
      const actualDurationMs = sessionExpiryTime.getTime() - testStartTime.getTime();
      const expectedDurationMs = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      const toleranceMs = 10000; // 10 seconds tolerance
      
      expect(actualDurationMs).toBeGreaterThanOrEqual(expectedDurationMs - toleranceMs);
      expect(actualDurationMs).toBeLessThanOrEqual(expectedDurationMs + toleranceMs);

      // Verify transaction was called
      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });
  });
});