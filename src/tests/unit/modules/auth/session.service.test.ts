import { SessionService } from '@/modules/auth/services/session.service';
import { prisma } from '@/core/database/prisma.client';
import { generateRefreshToken } from '@/modules/auth/utils/jwt.utils';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { env } from '@/core/config/env';

// Mock dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    session: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    refreshToken: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
  },
}));

jest.mock('@/modules/auth/utils/jwt.utils', () => ({
  generateRefreshToken: jest.fn(),
}));

jest.mock('@/core/config/env', () => ({
  env: {
    SESSION_EXPIRES_IN: '8h',
    REFRESH_TOKEN_EXPIRES_IN: '8h',
  },
}));

describe('SessionService', () => {
  let sessionService: SessionService;

  beforeEach(() => {
    sessionService = new SessionService();
    jest.clearAllMocks();
  });

  describe('createSession', () => {
    it('should create a new session', async () => {
      const options = {
        userId: 'user-123',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };
      const mockSession = {
        id: 'session-123',
        userId: options.userId,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        expiresAt: expect.any(Date),
        isActive: true,
      };

      (prisma.session.create as jest.Mock).mockResolvedValue(mockSession);

      const result = await sessionService.createSession(options);

      expect(result).toEqual(mockSession);
      expect(prisma.session.create).toHaveBeenCalledWith({
        data: {
          userId: options.userId,
          ipAddress: options.ipAddress,
          userAgent: options.userAgent,
          expiresAt: expect.any(Date),
          isActive: true,
        },
      });
    });

    it('should use transaction client when provided', async () => {
      const mockTx = {
        session: {
          create: jest.fn().mockResolvedValue({ id: 'session-123' }),
        },
      };

      await sessionService.createSession({
        userId: 'user-123',
        tx: mockTx as any,
      });

      expect(mockTx.session.create).toHaveBeenCalled();
      expect(prisma.session.create).not.toHaveBeenCalled();
    });
  });

  describe('createRefreshToken', () => {
    it('should create a new refresh token', async () => {
      const options = {
        userId: 'user-123',
        sessionId: 'session-123',
        deviceId: 'device-123',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };
      const mockToken = 'refresh-token-123';
      const mockRefreshToken = {
        id: 'token-123',
        userId: options.userId,
        sessionId: options.sessionId,
        token: mockToken,
        deviceId: options.deviceId,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        expiresAt: expect.any(Date),
      };

      (generateRefreshToken as jest.Mock).mockReturnValue(mockToken);
      (prisma.refreshToken.create as jest.Mock).mockResolvedValue(mockRefreshToken);

      const result = await sessionService.createRefreshToken(options);

      expect(result).toEqual(mockRefreshToken);
      expect(generateRefreshToken).toHaveBeenCalled();
      expect(prisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          userId: options.userId,
          sessionId: options.sessionId,
          token: mockToken,
          deviceId: options.deviceId,
          ipAddress: options.ipAddress,
          userAgent: options.userAgent,
          expiresAt: expect.any(Date),
        },
      });
    });
  });

  describe('getValidRefreshToken', () => {
    const mockValidToken = {
      id: 'token-123',
      token: 'refresh-token-123',
      isRevoked: false,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      session: {
        id: 'session-123',
        isActive: true,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
      user: {
        id: 'user-123',
        profile: {},
        organizationUsers: [],
      },
    };

    it('should return valid refresh token', async () => {
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(mockValidToken);

      const result = await sessionService.getValidRefreshToken('refresh-token-123');

      expect(result).toEqual(mockValidToken);
      expect(prisma.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { token: 'refresh-token-123' },
        include: {
          session: true,
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
    });

    it('should throw error for non-existent token', async () => {
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(sessionService.getValidRefreshToken('invalid-token')).rejects.toThrow(
        NotFoundError,
      );
      await expect(sessionService.getValidRefreshToken('invalid-token')).rejects.toThrow(
        'Invalid refresh token',
      );
    });

    it('should throw error for revoked token', async () => {
      const revokedToken = { ...mockValidToken, isRevoked: true };
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(revokedToken);

      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        'Refresh token has been revoked',
      );
    });

    it('should throw error for expired token', async () => {
      const expiredToken = {
        ...mockValidToken,
        expiresAt: new Date(Date.now() - 60 * 1000),
      };
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(expiredToken);

      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        'Refresh token has expired',
      );
    });

    it('should throw error for inactive session', async () => {
      const tokenWithInactiveSession = {
        ...mockValidToken,
        session: { ...mockValidToken.session, isActive: false },
      };
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(tokenWithInactiveSession);

      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        'Session has been terminated',
      );
    });

    it('should throw error for expired session', async () => {
      const tokenWithExpiredSession = {
        ...mockValidToken,
        session: {
          ...mockValidToken.session,
          expiresAt: new Date(Date.now() - 60 * 1000),
        },
      };
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue(tokenWithExpiredSession);

      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidRefreshToken('refresh-token-123')).rejects.toThrow(
        'Session has expired',
      );
    });
  });

  describe('rotateRefreshToken', () => {
    it('should rotate refresh token successfully', async () => {
      const oldToken = 'old-token-123';
      const newToken = 'new-token-123';
      const userId = 'user-123';
      const sessionId = 'session-123';
      const family = 'family-123';
      const ipAddress = '192.168.1.1';
      const userAgent = 'Mozilla/5.0';
      const deviceId = 'device-123';

      const mockNewToken = {
        id: 'token-new',
        userId,
        sessionId,
        token: newToken,
        family,
        deviceId,
        ipAddress,
        userAgent,
        expiresAt: expect.any(Date),
      };

      (generateRefreshToken as jest.Mock).mockReturnValue(newToken);
      (prisma.refreshToken.update as jest.Mock).mockResolvedValue({ isRevoked: true });
      (prisma.refreshToken.create as jest.Mock).mockResolvedValue(mockNewToken);

      const result = await sessionService.rotateRefreshToken(
        oldToken,
        userId,
        sessionId,
        family,
        ipAddress,
        userAgent,
        deviceId,
      );

      expect(result).toEqual(mockNewToken);
      expect(prisma.refreshToken.update).toHaveBeenCalledWith({
        where: { token: oldToken },
        data: { isRevoked: true },
      });
      expect(prisma.refreshToken.create).toHaveBeenCalledWith({
        data: {
          userId,
          sessionId,
          token: newToken,
          family,
          deviceId,
          ipAddress,
          userAgent,
          expiresAt: expect.any(Date),
        },
      });
    });
  });

  describe('getValidSession', () => {
    const mockValidSession = {
      id: 'session-123',
      isActive: true,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      user: {
        id: 'user-123',
        profile: {},
        organizationUsers: [],
      },
    };

    it('should return valid session', async () => {
      (prisma.session.findUnique as jest.Mock).mockResolvedValue(mockValidSession);

      const result = await sessionService.getValidSession('session-123');

      expect(result).toEqual(mockValidSession);
      expect(prisma.session.findUnique).toHaveBeenCalledWith({
        where: { id: 'session-123' },
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
    });

    it('should throw error for non-existent session', async () => {
      (prisma.session.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(sessionService.getValidSession('invalid-session')).rejects.toThrow(
        NotFoundError,
      );
      await expect(sessionService.getValidSession('invalid-session')).rejects.toThrow(
        'Invalid session',
      );
    });

    it('should throw error for inactive session', async () => {
      const inactiveSession = { ...mockValidSession, isActive: false };
      (prisma.session.findUnique as jest.Mock).mockResolvedValue(inactiveSession);

      await expect(sessionService.getValidSession('session-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidSession('session-123')).rejects.toThrow(
        'Session has been terminated',
      );
    });

    it('should throw error and deactivate expired session', async () => {
      const expiredSession = {
        ...mockValidSession,
        expiresAt: new Date(Date.now() - 60 * 1000),
      };
      (prisma.session.findUnique as jest.Mock).mockResolvedValue(expiredSession);
      (prisma.session.update as jest.Mock).mockResolvedValue({});

      await expect(sessionService.getValidSession('session-123')).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(sessionService.getValidSession('session-123')).rejects.toThrow(
        'Session has expired',
      );

      expect(prisma.session.update).toHaveBeenCalledWith({
        where: { id: 'session-123' },
        data: { isActive: false },
      });
    });
  });

  describe('deactivateSession', () => {
    it('should deactivate session and revoke its tokens', async () => {
      const sessionId = 'session-123';

      (prisma.session.update as jest.Mock).mockResolvedValue({});
      (prisma.refreshToken.updateMany as jest.Mock).mockResolvedValue({});

      await sessionService.deactivateSession(sessionId);

      expect(prisma.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: { isActive: false },
      });
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          sessionId,
          isRevoked: false,
        },
        data: { isRevoked: true },
      });
    });
  });

  describe('deactivateUserSessions', () => {
    it('should deactivate all user sessions', async () => {
      const userId = 'user-123';

      (prisma.session.updateMany as jest.Mock).mockResolvedValue({});

      await sessionService.deactivateUserSessions(userId);

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          userId,
          isActive: true,
        },
        data: { isActive: false },
      });
    });
  });

  describe('revokeUserRefreshTokens', () => {
    it('should revoke all user refresh tokens', async () => {
      const userId = 'user-123';

      (prisma.refreshToken.updateMany as jest.Mock).mockResolvedValue({});

      await sessionService.revokeUserRefreshTokens(userId);

      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          userId,
          isRevoked: false,
        },
        data: { isRevoked: true },
      });
    });
  });

  describe('cleanupExpired', () => {
    it('should cleanup expired sessions and tokens', async () => {
      const now = new Date();
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

      (prisma.session.updateMany as jest.Mock).mockResolvedValue({});
      (prisma.session.deleteMany as jest.Mock).mockResolvedValue({});
      (prisma.refreshToken.deleteMany as jest.Mock).mockResolvedValue({});

      await sessionService.cleanupExpired();

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          expiresAt: { lt: expect.any(Date) },
          isActive: true,
        },
        data: { isActive: false },
      });
      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: {
          expiresAt: { lt: expect.any(Date) },
        },
      });
      expect(prisma.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: {
          expiresAt: { lt: expect.any(Date) },
        },
      });
    });
  });
});
