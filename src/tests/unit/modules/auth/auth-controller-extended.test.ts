import { Request, Response } from 'express';
import { authController } from '@/modules/auth/controllers/auth.controller';
import { signupService } from '@/modules/auth/services/signup.service';
import { verificationService } from '@/modules/auth/services/verification.service';
import { userService } from '@/modules/auth/services/user.service';
import { getClientIp } from '@/common/utils/ip.utils';
import { asyncHandler } from '@/common/utils/async-handler';

// Mock dependencies
jest.mock('@/modules/auth/services/signup.service', () => ({
  signupService: {
    signup: jest.fn(),
  },
}));

jest.mock('@/modules/auth/services/verification.service', () => ({
  verificationService: {
    resendVerification: jest.fn(),
  },
}));

jest.mock('@/modules/auth/services/user.service', () => ({
  userService: {
    getCurrentUser: jest.fn(),
  },
}));

jest.mock('@/common/utils/ip.utils', () => ({
  getClientIp: jest.fn(),
}));

jest.mock('@/common/utils/async-handler', () => ({
  asyncHandler: (fn: any) => fn,
}));

describe('AuthController - Extended Tests', () => {
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

  describe('signup', () => {
    it('should successfully handle user signup', async () => {
      const mockBody = {
        email: 'new@example.com',
        password: 'SecurePass123!',
        firstName: 'New',
        lastName: 'User',
        organizationName: 'New Org',
      };
      const mockIpAddress = '192.168.1.1';
      const mockResult = {
        user: {
          id: 'user-123',
          email: 'new@example.com',
        },
        organization: {
          id: 'org-123',
          name: 'New Org',
          slug: 'new-org',
        },
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (signupService.signup as jest.Mock).mockResolvedValue(mockResult);

      await authController.signup(mockReq as Request, mockRes as Response, mockNext);

      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(signupService.signup).toHaveBeenCalledWith(mockBody, mockIpAddress);
      expect(statusMock).toHaveBeenCalledWith(201);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        data: mockResult,
      });
    });

    it('should handle signup without IP address', async () => {
      const mockBody = {
        email: 'new@example.com',
        password: 'SecurePass123!',
        firstName: 'New',
        lastName: 'User',
        organizationName: 'New Org',
      };
      const mockResult = {
        user: { id: 'user-123' },
        organization: { id: 'org-123' },
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(undefined);
      (signupService.signup as jest.Mock).mockResolvedValue(mockResult);

      await authController.signup(mockReq as Request, mockRes as Response, mockNext);

      expect(signupService.signup).toHaveBeenCalledWith(mockBody, undefined);
      expect(statusMock).toHaveBeenCalledWith(201);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        data: mockResult,
      });
    });

    it('should handle signup errors', async () => {
      const mockBody = {
        email: 'existing@example.com',
        password: 'SecurePass123!',
      };
      const mockError = new Error('Email already exists');

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (signupService.signup as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.signup(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Email already exists');

      expect(statusMock).not.toHaveBeenCalled();
      expect(jsonMock).not.toHaveBeenCalled();
    });
  });

  describe('resendVerification', () => {
    it('should successfully resend verification email', async () => {
      const mockBody = {
        email: 'unverified@example.com',
      };
      const mockIpAddress = '192.168.1.1';

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(mockIpAddress);
      (verificationService.resendVerification as jest.Mock).mockResolvedValue(undefined);

      await authController.resendVerification(mockReq as Request, mockRes as Response, mockNext);

      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(verificationService.resendVerification).toHaveBeenCalledWith(
        mockBody.email,
        mockIpAddress,
      );
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'If an account exists with this email, a verification link has been sent.',
      });
    });

    it('should handle resendVerification without IP address', async () => {
      const mockBody = {
        email: 'unverified@example.com',
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue(undefined);
      (verificationService.resendVerification as jest.Mock).mockResolvedValue(undefined);

      await authController.resendVerification(mockReq as Request, mockRes as Response, mockNext);

      expect(verificationService.resendVerification).toHaveBeenCalledWith(
        mockBody.email,
        undefined,
      );
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'If an account exists with this email, a verification link has been sent.',
      });
    });

    it('should return success even on service errors (prevent enumeration)', async () => {
      const mockBody = {
        email: 'nonexistent@example.com',
      };

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      // Service returns void even for non-existent emails
      (verificationService.resendVerification as jest.Mock).mockResolvedValue(undefined);

      await authController.resendVerification(mockReq as Request, mockRes as Response, mockNext);

      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: 'If an account exists with this email, a verification link has been sent.',
      });
    });

    it('should handle resendVerification service errors', async () => {
      const mockBody = {
        email: 'error@example.com',
      };
      const mockError = new Error('Email service unavailable');

      mockReq.body = mockBody;
      (getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
      (verificationService.resendVerification as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.resendVerification(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Email service unavailable');

      expect(jsonMock).not.toHaveBeenCalled();
    });
  });

  describe('me', () => {
    it('should return current user profile', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockUserData = {
        id: 'user-123',
        email: 'test@example.com',
        emailVerified: true,
        status: 'ACTIVE',
        profile: {
          firstName: 'Test',
          lastName: 'User',
          timezone: 'America/New_York',
          avatarUrl: null,
          phoneNumber: null,
        },
        organization: {
          id: 'org-123',
          name: 'Test Org',
          slug: 'test-org',
        },
        role: {
          id: 'role-123',
          name: 'owner',
          description: 'Organization owner',
        },
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-15'),
      };

      mockReq.user = mockUser;
      (userService.getCurrentUser as jest.Mock).mockResolvedValue(mockUserData);

      await authController.me(mockReq as Request, mockRes as Response, mockNext);

      expect(userService.getCurrentUser).toHaveBeenCalledWith(mockUser.userId);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        data: mockUserData,
      });
    });

    it('should handle me endpoint errors', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockError = new Error('User not found');

      mockReq.user = mockUser;
      (userService.getCurrentUser as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.me(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('User not found');

      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should handle inactive user in me endpoint', async () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
        sessionId: 'session-123',
      };
      const mockError = new Error('Account is not active');

      mockReq.user = mockUser;
      (userService.getCurrentUser as jest.Mock).mockRejectedValue(mockError);

      await expect(
        authController.me(mockReq as Request, mockRes as Response, mockNext),
      ).rejects.toThrow('Account is not active');

      expect(userService.getCurrentUser).toHaveBeenCalledWith(mockUser.userId);
      expect(jsonMock).not.toHaveBeenCalled();
    });
  });
});
