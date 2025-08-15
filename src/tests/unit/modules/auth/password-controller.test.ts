import { Request, Response } from 'express';
import { authController } from '@/modules/auth/controllers/auth.controller';
import { passwordService } from '@/modules/auth/services/password.service';
import { getClientIp } from '@/common/utils/ip.utils';
import { asyncHandler } from '@/common/utils/async-handler';

// Mock dependencies
jest.mock('@/modules/auth/services/password.service', () => ({
  passwordService: {
    changePassword: jest.fn(),
    forgotPassword: jest.fn(),
    resetPassword: jest.fn(),
  },
}));

jest.mock('@/common/utils/ip.utils', () => ({
  getClientIp: jest.fn(),
}));

jest.mock('@/common/utils/async-handler', () => ({
  asyncHandler: (fn: any) => fn,
}));

describe('AuthController - Password Methods', () => {
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
      headers: {},
      user: undefined,
    };

    mockRes = {
      json: jsonMock,
      status: statusMock,
    };

    jest.clearAllMocks();
  });

  describe('changePassword', () => {
    it('should successfully change password', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockBody = {
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        logoutAllDevices: true,
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.user = mockUser;
      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (passwordService.changePassword as jest.Mock).mockResolvedValue(undefined);

      await authController.changePassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.changePassword).toHaveBeenCalledWith({
        userId: mockUser.userId,
        currentPassword: mockBody.currentPassword,
        newPassword: mockBody.newPassword,
        logoutAllDevices: mockBody.logoutAllDevices,
        ipAddress: mockIpAddress,
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Password changed successfully. You have been logged out from all devices.',
      });
    });

    it('should handle changePassword without logoutAllDevices', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockBody = {
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!',
        // logoutAllDevices not provided, should default to false
      };

      mockReq.user = mockUser;
      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (passwordService.changePassword as jest.Mock).mockResolvedValue(undefined);

      await authController.changePassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.changePassword).toHaveBeenCalledWith({
        userId: mockUser.userId,
        currentPassword: mockBody.currentPassword,
        newPassword: mockBody.newPassword,
        logoutAllDevices: undefined,
        ipAddress: '192.168.1.1',
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Password changed successfully.',
      });
    });

    it('should handle changePassword errors', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockBody = {
        currentPassword: 'WrongPass123!',
        newPassword: 'NewPass456!',
      };
      const mockError = new Error('Current password is incorrect');

      mockReq.user = mockUser;
      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (passwordService.changePassword as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.changePassword(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Current password is incorrect');

      expect(jsonMock).not.toHaveBeenCalled();
    });
  });

  describe('forgotPassword', () => {
    it('should successfully request password reset', async () => {
      const mockBody = {
        email: 'test@example.com',
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (passwordService.forgotPassword as jest.Mock).mockResolvedValue(undefined);

      await authController.forgotPassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.forgotPassword).toHaveBeenCalledWith({
        email: mockBody.email,
        ipAddress: mockIpAddress,
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent.',
      });
    });

    it('should handle forgotPassword without IP address', async () => {
      const mockBody = {
        email: 'test@example.com',
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(undefined);
      (passwordService.forgotPassword as jest.Mock).mockResolvedValue(undefined);

      await authController.forgotPassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.forgotPassword).toHaveBeenCalledWith({
        email: mockBody.email,
        ipAddress: undefined,
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent.',
      });
    });

    it('should handle forgotPassword errors', async () => {
      const mockBody = {
        email: 'test@example.com',
      };
      const mockError = new Error('Email service unavailable');

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (passwordService.forgotPassword as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.forgotPassword(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Email service unavailable');

      expect(jsonMock).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    it('should successfully reset password', async () => {
      const mockBody = {
        token: 'reset-token-123',
        newPassword: 'NewSecurePass789!',
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (passwordService.resetPassword as jest.Mock).mockResolvedValue(undefined);

      await authController.resetPassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.resetPassword).toHaveBeenCalledWith({
        token: mockBody.token,
        newPassword: mockBody.newPassword,
        ipAddress: mockIpAddress,
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Password reset successfully. Please login with your new password.',
      });
    });

    it('should handle resetPassword without IP address', async () => {
      const mockBody = {
        token: 'reset-token-123',
        newPassword: 'NewSecurePass789!',
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(undefined);
      (passwordService.resetPassword as jest.Mock).mockResolvedValue(undefined);

      await authController.resetPassword(mockReq as Request, mockRes as Response, mockNext);

      expect(passwordService.resetPassword).toHaveBeenCalledWith({
        token: mockBody.token,
        newPassword: mockBody.newPassword,
        ipAddress: undefined,
      });
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'Password reset successfully. Please login with your new password.',
      });
    });

    it('should handle resetPassword with invalid token error', async () => {
      const mockBody = {
        token: 'invalid-token',
        newPassword: 'NewSecurePass789!',
      };
      const mockError = new Error('Invalid or expired reset token');

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (passwordService.resetPassword as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.resetPassword(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Invalid or expired reset token');

      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should handle resetPassword with password validation error', async () => {
      const mockBody = {
        token: 'reset-token-123',
        newPassword: 'weak',
      };
      const mockError = new Error('Password does not meet requirements');

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (passwordService.resetPassword as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.resetPassword(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Password does not meet requirements');

      expect(jsonMock).not.toHaveBeenCalled();
    });
  });
});
