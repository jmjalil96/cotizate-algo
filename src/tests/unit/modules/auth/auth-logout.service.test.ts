import { AuthService } from '@/modules/auth/services/auth.service';
import { prisma } from '@/core/database/prisma.client';
import { sessionService } from '@/modules/auth/services/session.service';
import { auditService } from '@/modules/shared/services/audit.service';

// Mock dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/services/session.service', () => ({
  sessionService: {
    deactivateSession: jest.fn(),
    deactivateUserSessions: jest.fn(),
    revokeUserRefreshTokens: jest.fn(),
  },
}));

jest.mock('@/modules/shared/services/audit.service', () => ({
  auditService: {
    logAction: jest.fn(),
  },
}));

describe('AuthService - Logout Tests', () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
    jest.clearAllMocks();
  });

  describe('logout', () => {
    it('should logout specific session when sessionId provided', async () => {
      const userId = 'user-123';
      const sessionId = 'session-123';
      const ipAddress = '192.168.1.1';

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        return callback(mockTx);
      });

      await authService.logout(userId, sessionId, ipAddress);

      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify transaction callback was executed
      const transactionCallback = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {};
      await transactionCallback(mockTx);

      expect(sessionService.deactivateSession).toHaveBeenCalledWith(sessionId, mockTx);
      expect(sessionService.deactivateUserSessions).not.toHaveBeenCalled();
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId,
          action: 'auth.logout',
          resource: 'auth',
          details: {
            sessionId: sessionId,
          },
          ipAddress,
        },
        mockTx,
      );
    });

    it('should logout all sessions when no sessionId provided', async () => {
      const userId = 'user-123';
      const ipAddress = '192.168.1.1';

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        return callback(mockTx);
      });

      await authService.logout(userId, undefined, ipAddress);

      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify transaction callback was executed
      const transactionCallback = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {};
      await transactionCallback(mockTx);

      expect(sessionService.deactivateSession).not.toHaveBeenCalled();
      expect(sessionService.deactivateUserSessions).toHaveBeenCalledWith(userId, mockTx);
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId,
          action: 'auth.logout',
          resource: 'auth',
          details: {
            sessionId: 'all',
          },
          ipAddress,
        },
        mockTx,
      );
    });

    it('should handle logout without IP address', async () => {
      const userId = 'user-123';
      const sessionId = 'session-123';

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        return callback(mockTx);
      });

      await authService.logout(userId, sessionId);

      const transactionCallback = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {};
      await transactionCallback(mockTx);

      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId,
          action: 'auth.logout',
          resource: 'auth',
          details: {
            sessionId: sessionId,
          },
          ipAddress: undefined,
        },
        mockTx,
      );
    });

    it('should rollback transaction on error', async () => {
      const userId = 'user-123';
      const sessionId = 'session-123';
      const mockError = new Error('Database error');

      (prisma.$transaction as jest.Mock).mockRejectedValue(mockError);

      await expect(authService.logout(userId, sessionId)).rejects.toThrow('Database error');

      expect(prisma.$transaction).toHaveBeenCalled();
    });
  });

  describe('logoutAll', () => {
    it('should deactivate all sessions and revoke all tokens', async () => {
      const userId = 'user-123';
      const ipAddress = '192.168.1.1';

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        return callback(mockTx);
      });

      await authService.logoutAll(userId, ipAddress);

      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify transaction callback was executed
      const transactionCallback = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {};
      await transactionCallback(mockTx);

      expect(sessionService.deactivateUserSessions).toHaveBeenCalledWith(userId, mockTx);
      expect(sessionService.revokeUserRefreshTokens).toHaveBeenCalledWith(userId, mockTx);
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId,
          action: 'auth.logout.all',
          resource: 'auth',
          details: {
            reason: 'user_initiated',
          },
          ipAddress,
        },
        mockTx,
      );
    });

    it('should handle logoutAll without IP address', async () => {
      const userId = 'user-123';

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        return callback(mockTx);
      });

      await authService.logoutAll(userId);

      const transactionCallback = (prisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {};
      await transactionCallback(mockTx);

      expect(sessionService.deactivateUserSessions).toHaveBeenCalledWith(userId, mockTx);
      expect(sessionService.revokeUserRefreshTokens).toHaveBeenCalledWith(userId, mockTx);
      expect(auditService.logAction).toHaveBeenCalledWith(
        {
          userId,
          action: 'auth.logout.all',
          resource: 'auth',
          details: {
            reason: 'user_initiated',
          },
          ipAddress: undefined,
        },
        mockTx,
      );
    });

    it('should rollback transaction on error during deactivation', async () => {
      const userId = 'user-123';
      const mockError = new Error('Session deactivation failed');

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        (sessionService.deactivateUserSessions as jest.Mock).mockRejectedValue(mockError);
        return callback(mockTx);
      });

      await expect(authService.logoutAll(userId)).rejects.toThrow('Session deactivation failed');
    });

    it('should rollback transaction on error during token revocation', async () => {
      const userId = 'user-123';
      const mockError = new Error('Token revocation failed');

      // Reset mocks for this specific test
      (sessionService.deactivateUserSessions as jest.Mock).mockResolvedValue(undefined);
      (sessionService.revokeUserRefreshTokens as jest.Mock).mockRejectedValue(mockError);

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        try {
          await callback(mockTx);
        } catch (error) {
          throw error;
        }
      });

      await expect(authService.logoutAll(userId)).rejects.toThrow('Token revocation failed');
    });

    it('should rollback transaction on audit log error', async () => {
      const userId = 'user-123';
      const mockError = new Error('Audit log failed');

      // Reset mocks for this specific test
      (sessionService.deactivateUserSessions as jest.Mock).mockResolvedValue(undefined);
      (sessionService.revokeUserRefreshTokens as jest.Mock).mockResolvedValue(undefined);
      (auditService.logAction as jest.Mock).mockRejectedValue(mockError);

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {};
        try {
          await callback(mockTx);
        } catch (error) {
          throw error;
        }
      });

      await expect(authService.logoutAll(userId)).rejects.toThrow('Audit log failed');
    });
  });
});
