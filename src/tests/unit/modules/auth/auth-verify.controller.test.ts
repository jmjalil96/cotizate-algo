import { Request, Response, NextFunction } from 'express';
import { AuthController } from '@/modules/auth/controllers/auth.controller';
import { authService } from '@/modules/auth/services/auth.service';
import { verificationService } from '@/modules/auth/services/verification.service';
import { getClientIp } from '@/common/utils/ip.utils';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import type { EmailVerificationInput } from '@/modules/auth/validators/auth.schema';

// Mock dependencies
jest.mock('@/modules/auth/services/auth.service');
jest.mock('@/modules/auth/services/verification.service');
jest.mock('@/common/utils/ip.utils');

describe('AuthController - Verify Endpoint', () => {
  let authController: AuthController;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    authController = new AuthController();

    // Reset all mocks
    jest.clearAllMocks();

    // Setup response mock - verify doesn't use status(), only json()
    mockRes = {
      json: jest.fn().mockReturnThis(),
    };

    // Setup next function mock
    mockNext = jest.fn();
  });

  describe('verify', () => {
    it('should extract IP and user agent from request', async () => {
      // Arrange
      const verificationToken = 'valid-verification-token-123';
      const expectedIp = '192.168.10.50';
      const expectedUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0';

      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      mockReq = {
        body: verifyData,
        headers: {
          'user-agent': expectedUserAgent,
          'x-forwarded-for': '192.168.10.50, 10.0.0.1',
        },
        ip: '127.0.0.1',
        socket: {
          remoteAddress: '::1',
        } as any,
      };

      const mockServiceResult = {
        accessToken: 'jwt.access.token',
        refreshToken: 'refresh-token-123',
        user: {
          id: 'user-123',
          email: 'verified@example.com',
          firstName: 'John',
          lastName: 'Doe',
        },
        organization: {
          id: 'org-123',
          name: 'Test Organization',
          slug: 'test-organization',
        },
      };

      // Mock getClientIp to return the expected IP
      (getClientIp as jest.Mock).mockReturnValue(expectedIp);

      // Mock verificationService.verify
      (verificationService.verify as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.verify(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify getClientIp was called with the request
      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(getClientIp).toHaveBeenCalledTimes(1);

      // Verify verificationService.verify was called with token, IP, and user agent
      expect(verificationService.verify).toHaveBeenCalledWith(
        verificationToken,
        expectedIp,
        expectedUserAgent,
      );

      // Verify the user agent was correctly extracted from headers
      expect(verificationService.verify).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expectedUserAgent,
      );
    });

    it('should pass token to service', async () => {
      // Arrange
      const verificationToken = 'specific-token-to-verify-abc123';
      const clientIp = '10.20.30.40';
      const userAgent = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0';

      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      mockReq = {
        body: verifyData,
        headers: {
          'user-agent': userAgent,
        },
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      const mockServiceResult = {
        accessToken: 'jwt.access.token.456',
        refreshToken: 'refresh-token-456',
        user: {
          id: 'user-456',
          email: 'token-test@example.com',
          firstName: 'Jane',
          lastName: 'Smith',
        },
        organization: {
          id: 'org-456',
          name: 'Token Test Org',
          slug: 'token-test-org',
        },
      };

      // Mock dependencies
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.verify(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify the service was called with the exact token from the request body
      expect(verificationService.verify).toHaveBeenCalledWith(
        verificationToken,
        clientIp,
        userAgent,
      );

      // Verify the service was called exactly once
      expect(verificationService.verify).toHaveBeenCalledTimes(1);

      // Verify each parameter was passed correctly
      const callArgs = (verificationService.verify as jest.Mock).mock.calls[0];
      expect(callArgs[0]).toBe(verificationToken);
      expect(callArgs[1]).toBe(clientIp);
      expect(callArgs[2]).toBe(userAgent);

      // Verify the token is extracted from req.body.token specifically
      expect(callArgs[0]).toBe(mockReq.body.token);
    });

    it('should return 200 status on success', async () => {
      // Arrange
      const verificationToken = 'success-token-789xyz';
      const clientIp = '172.20.0.50';
      const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/14.1';

      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      mockReq = {
        body: verifyData,
        headers: {
          'user-agent': userAgent,
        },
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      const mockServiceResult = {
        accessToken: 'jwt.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.success',
        refreshToken: 'refresh-token-success-789',
        user: {
          id: 'user-success-789',
          email: 'success@example.com',
          firstName: 'Success',
          lastName: 'User',
        },
        organization: {
          id: 'org-success-789',
          name: 'Success Organization',
          slug: 'success-organization',
        },
      };

      // Mock dependencies
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.verify(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify json response was sent with correct structure (no status call as 200 is default)
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        data: mockServiceResult,
      });
      expect(mockRes.json).toHaveBeenCalledTimes(1);

      // Verify the exact response data structure
      const jsonCall = (mockRes.json as jest.Mock).mock.calls[0][0];
      expect(jsonCall).toHaveProperty('success', true);
      expect(jsonCall).toHaveProperty('data');
      expect(jsonCall.data).toEqual(mockServiceResult);

      // Verify specific fields in the response
      expect(jsonCall.data.accessToken).toBe('jwt.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.success');
      expect(jsonCall.data.refreshToken).toBe('refresh-token-success-789');
      expect(jsonCall.data.user.id).toBe('user-success-789');
      expect(jsonCall.data.user.email).toBe('success@example.com');
      expect(jsonCall.data.user.firstName).toBe('Success');
      expect(jsonCall.data.user.lastName).toBe('User');
      expect(jsonCall.data.organization.id).toBe('org-success-789');
      expect(jsonCall.data.organization.name).toBe('Success Organization');
      expect(jsonCall.data.organization.slug).toBe('success-organization');

      // Note: Unlike signup, verify doesn't call res.status() as it uses default 200
      // So we don't test for status call
    });

    it('should handle service errors properly', async () => {
      // Arrange
      const verificationToken = 'error-test-token';
      const clientIp = '203.0.113.100';
      const userAgent = 'Mozilla/5.0 Error Test Agent';

      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      mockReq = {
        body: verifyData,
        headers: {
          'user-agent': userAgent,
        },
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      // Test with NotFoundError (invalid token)
      const notFoundError = new NotFoundError('Invalid or expired verification token');

      // Mock dependencies
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockRejectedValue(notFoundError);

      // Act & Assert - NotFoundError
      try {
        await authController.verify(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        // The error should bubble up since we're calling the method directly
        expect(error).toBe(notFoundError);
      }

      // Verify response methods were not called when error occurs
      expect(mockRes.json).not.toHaveBeenCalled();

      // Verify service was called with correct parameters
      expect(verificationService.verify).toHaveBeenCalledWith(
        verificationToken,
        clientIp,
        userAgent,
      );
      expect(verificationService.verify).toHaveBeenCalledTimes(1);

      // Reset mocks for next test
      jest.clearAllMocks();
      mockRes.json = jest.fn().mockReturnThis();

      // Test with UnauthorizedError (expired token)
      const unauthorizedError = new UnauthorizedError('Verification token has expired');
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockRejectedValue(unauthorizedError);

      // Act & Assert - UnauthorizedError
      try {
        await authController.verify(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        expect(error).toBe(unauthorizedError);
      }

      // Verify response not sent
      expect(mockRes.json).not.toHaveBeenCalled();

      // Reset mocks for organization not found test
      jest.clearAllMocks();
      mockRes.json = jest.fn().mockReturnThis();

      // Test with NotFoundError (organization not found)
      const orgNotFoundError = new NotFoundError('Organization not found');
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockRejectedValue(orgNotFoundError);

      // Act & Assert - Organization NotFoundError
      try {
        await authController.verify(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        expect(error).toBe(orgNotFoundError);
      }

      // Verify response not sent
      expect(mockRes.json).not.toHaveBeenCalled();

      // Reset mocks for generic error test
      jest.clearAllMocks();
      mockRes.json = jest.fn().mockReturnThis();

      // Test with generic error
      const genericError = new Error('Unexpected database error');
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (verificationService.verify as jest.Mock).mockRejectedValue(genericError);

      // Act & Assert - Generic Error
      try {
        await authController.verify(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        expect(error).toEqual(genericError);
      }

      // Verify response not sent on error
      expect(mockRes.json).not.toHaveBeenCalled();

      // Verify service was called before error
      expect(verificationService.verify).toHaveBeenCalledWith(
        verificationToken,
        clientIp,
        userAgent,
      );
    });
  });
});
