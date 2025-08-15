import { Request, Response } from 'express';
import { authController } from '@/modules/auth/controllers/auth.controller';
import { authService } from '@/modules/auth/services/auth.service';
import { getClientIp } from '@/common/utils/ip.utils';
import { asyncHandler } from '@/common/utils/async-handler';

// Mock dependencies
jest.mock('@/modules/auth/services/auth.service', () => ({
  authService: {
    refresh: jest.fn(),
    logout: jest.fn(),
    logoutAll: jest.fn(),
  },
}));

jest.mock('@/common/utils/ip.utils', () => ({
  getClientIp: jest.fn(),
}));

jest.mock('@/common/utils/async-handler', () => ({
  asyncHandler: (fn: any) => fn,
}));

describe('AuthController', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnThis();
    mockNext = jest.fn();

    mockReq = {
      body: {},
      headers: {
        'user-agent': 'Mozilla/5.0',
      },
      user: undefined,
    };

    mockRes = {
      json: jsonMock,
      status: statusMock,
    };

    jest.clearAllMocks();
  });

  describe('refresh', () => {
    it('should successfully refresh tokens', async () => {
      const mockRefreshToken = 'refresh-token-123';
      const mockIpAddress = '192.168.1.1';
      const mockResult = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        user: {
          id: 'user-123',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
        },
        organization: {
          id: 'org-123',
          name: 'Test Org',
          slug: 'test-org',
        },
      };

      mockReq.body = { refreshToken: mockRefreshToken };
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.refresh as jest.Mock).mockResolvedValue(mockResult);

      await authController.refresh(mockReq as Request, mockRes as Response, mockNext);

      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(authService.refresh).toHaveBeenCalledWith(
        mockRefreshToken,
        mockIpAddress,
        'Mozilla/5.0',
      );
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        data: mockResult,
      });
    });

    it('should handle refresh errors', async () => {
      const mockRefreshToken = 'invalid-token';
      const mockIpAddress = '192.168.1.1';
      const mockError = new Error('Invalid refresh token');

      mockReq.body = { refreshToken: mockRefreshToken };
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.refresh as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.refresh(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Invalid refresh token');

      expect(authService.refresh).toHaveBeenCalledWith(
        mockRefreshToken,
        mockIpAddress,
        'Mozilla/5.0',
      );
      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should handle missing user agent', async () => {
      const mockRefreshToken = 'refresh-token-123';
      const mockIpAddress = '192.168.1.1';
      const mockResult = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        user: { id: 'user-123' },
        organization: { id: 'org-123' },
      };

      mockReq.body = { refreshToken: mockRefreshToken };
      mockReq.headers = {}; // No user-agent
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.refresh as jest.Mock).mockResolvedValue(mockResult);

      await authController.refresh(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.refresh).toHaveBeenCalledWith(mockRefreshToken, mockIpAddress, undefined);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        data: mockResult,
      });
    });
  });

  describe('logout', () => {
    it('should successfully logout user from current session', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.logout as jest.Mock).mockResolvedValue(undefined);

      await authController.logout(mockReq as Request, mockRes as Response, mockNext);

      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(authService.logout).toHaveBeenCalledWith(
        mockUser.userId,
        mockUser.sessionId,
        mockIpAddress,
      );
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Logged out successfully',
      });
    });

    it('should handle logout errors', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockIpAddress = '192.168.1.1';
      const mockError = new Error('Logout failed');

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.logout as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.logout(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Logout failed');

      expect(authService.logout).toHaveBeenCalledWith(
        mockUser.userId,
        mockUser.sessionId,
        mockIpAddress,
      );
      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should handle missing IP address', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(undefined);
      (authService.logout as jest.Mock).mockResolvedValue(undefined);

      await authController.logout(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.logout).toHaveBeenCalledWith(
        mockUser.userId,
        mockUser.sessionId,
        undefined,
      );
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Logged out successfully',
      });
    });
  });

  describe('logoutAll', () => {
    it('should successfully logout user from all devices', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.logoutAll as jest.Mock).mockResolvedValue(undefined);

      await authController.logoutAll(mockReq as Request, mockRes as Response, mockNext);

      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(authService.logoutAll).toHaveBeenCalledWith(mockUser.userId, mockIpAddress);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Logged out from all devices successfully',
      });
    });

    it('should handle logoutAll errors', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockIpAddress = '192.168.1.1';
      const mockError = new Error('LogoutAll failed');

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.logoutAll as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.logoutAll(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('LogoutAll failed');

      expect(authService.logoutAll).toHaveBeenCalledWith(mockUser.userId, mockIpAddress);
      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should handle user without sessionId in logoutAll', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: undefined, // No sessionId
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.user = mockUser;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (authService.logoutAll as jest.Mock).mockResolvedValue(undefined);

      await authController.logoutAll(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.logoutAll).toHaveBeenCalledWith(mockUser.userId, mockIpAddress);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Logged out from all devices successfully',
      });
    });
  });
});
