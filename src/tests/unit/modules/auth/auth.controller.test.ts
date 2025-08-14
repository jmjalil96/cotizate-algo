import { Request, Response, NextFunction } from 'express';
import { AuthController } from '@/modules/auth/controllers/auth.controller';
import { authService } from '@/modules/auth/services/auth.service';
import { getClientIp } from '@/common/utils/ip.utils';
import { ConflictError, ValidationError } from '@/common/exceptions/app.error';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

// Mock dependencies
jest.mock('@/modules/auth/services/auth.service');
jest.mock('@/common/utils/ip.utils');

describe('AuthController', () => {
  let authController: AuthController;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    authController = new AuthController();
    
    // Reset all mocks
    jest.clearAllMocks();

    // Setup response mock
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    // Setup next function mock
    mockNext = jest.fn();
  });

  describe('signup', () => {
    it('should extract IP address from request', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        organizationName: 'Test Organization',
        password: 'SecurePass123!',
      };

      const expectedIp = '192.168.1.100';
      
      mockReq = {
        body: signupData,
        headers: {
          'x-forwarded-for': '192.168.1.100, 10.0.0.1',
        },
        ip: '127.0.0.1',
        socket: {
          remoteAddress: '::1',
        } as any,
      };

      const mockServiceResult = {
        message: 'Account created successfully',
        user: {
          id: 'user-123',
          email: signupData.email,
        },
        organization: {
          id: 'org-123',
          name: signupData.organizationName,
          slug: 'test-organization',
        },
      };

      // Mock getClientIp to return the expected IP
      (getClientIp as jest.Mock).mockReturnValue(expectedIp);
      
      // Mock authService.signup
      (authService.signup as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.signup(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify getClientIp was called with the request
      expect(getClientIp).toHaveBeenCalledWith(mockReq);
      expect(getClientIp).toHaveBeenCalledTimes(1);

      // Verify authService.signup was called with the extracted IP
      expect(authService.signup).toHaveBeenCalledWith(
        signupData,
        expectedIp
      );
    });

    it('should pass data to service correctly', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        organizationName: 'Smith Corp',
        password: 'AnotherPass456!',
      };

      const clientIp = '10.0.0.50';
      
      mockReq = {
        body: signupData,
        headers: {},
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      const mockServiceResult = {
        message: 'Account created successfully',
        user: {
          id: 'user-456',
          email: signupData.email,
        },
        organization: {
          id: 'org-456', 
          name: signupData.organizationName,
          slug: 'smith-corp',
        },
      };

      // Mock IP extraction
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      
      // Mock service call
      (authService.signup as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.signup(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify the service was called with the exact data from the request body
      expect(authService.signup).toHaveBeenCalledWith(
        signupData,
        clientIp
      );
      
      // Verify the service was called exactly once
      expect(authService.signup).toHaveBeenCalledTimes(1);
      
      // Verify each field was passed correctly
      const callArgs = (authService.signup as jest.Mock).mock.calls[0];
      expect(callArgs[0]).toEqual(signupData);
      expect(callArgs[0].firstName).toBe('Jane');
      expect(callArgs[0].lastName).toBe('Smith');
      expect(callArgs[0].email).toBe('jane.smith@example.com');
      expect(callArgs[0].organizationName).toBe('Smith Corp');
      expect(callArgs[0].password).toBe('AnotherPass456!');
      expect(callArgs[1]).toBe(clientIp);
    });

    it('should return 201 status on success', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob.johnson@example.com',
        organizationName: 'Johnson Industries',
        password: 'BobPassword789!',
      };

      const clientIp = '172.16.0.100';
      
      mockReq = {
        body: signupData,
        headers: {},
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      const mockServiceResult = {
        message: 'Account created successfully. Please check your email to verify your account.',
        user: {
          id: 'user-789',
          email: signupData.email,
        },
        organization: {
          id: 'org-789',
          name: signupData.organizationName,
          slug: 'johnson-industries',
        },
      };

      // Mock dependencies
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (authService.signup as jest.Mock).mockResolvedValue(mockServiceResult);

      // Act
      await authController.signup(mockReq as Request, mockRes as Response, mockNext);

      // Assert
      // Verify status 201 was set
      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.status).toHaveBeenCalledTimes(1);

      // Verify json response was sent with correct structure
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
      expect(jsonCall.data.message).toBe('Account created successfully. Please check your email to verify your account.');
      expect(jsonCall.data.user.id).toBe('user-789');
      expect(jsonCall.data.organization.slug).toBe('johnson-industries');
    });

    it('should handle service errors properly', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Alice',
        lastName: 'Williams',
        email: 'alice.williams@example.com',
        organizationName: 'Williams LLC',
        password: 'AlicePass321!',
      };

      const clientIp = '203.0.113.42';
      
      mockReq = {
        body: signupData,
        headers: {},
        ip: clientIp,
        socket: {
          remoteAddress: clientIp,
        } as any,
      };

      // Test with ConflictError (email already exists)
      const conflictError = new ConflictError('Email already registered');
      
      // Mock dependencies
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (authService.signup as jest.Mock).mockRejectedValue(conflictError);

      // Act - The method doesn't return a promise directly, it's wrapped by asyncHandler
      // So we need to test the actual behavior when an error occurs
      try {
        await authController.signup(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        // The error should bubble up since we're calling the method directly
        expect(error).toBe(conflictError);
      }

      // Verify response methods were not called when error occurs
      expect(mockRes.status).not.toHaveBeenCalled();
      expect(mockRes.json).not.toHaveBeenCalled();

      // Verify service was called with correct parameters
      expect(authService.signup).toHaveBeenCalledWith(signupData, clientIp);
      expect(authService.signup).toHaveBeenCalledTimes(1);

      // Reset mocks for next test
      jest.clearAllMocks();
      mockRes.status = jest.fn().mockReturnThis();
      mockRes.json = jest.fn().mockReturnThis();

      // Test with ValidationError
      const validationError = new ValidationError('Invalid input data');
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (authService.signup as jest.Mock).mockRejectedValue(validationError);

      // Act & Assert - ValidationError
      try {
        await authController.signup(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        expect(error).toBe(validationError);
      }

      // Verify response not sent
      expect(mockRes.status).not.toHaveBeenCalled();
      expect(mockRes.json).not.toHaveBeenCalled();

      // Reset mocks for generic error test
      jest.clearAllMocks();
      mockRes.status = jest.fn().mockReturnThis();
      mockRes.json = jest.fn().mockReturnThis();

      // Test with generic error
      const genericError = new Error('Database connection failed');
      (getClientIp as jest.Mock).mockReturnValue(clientIp);
      (authService.signup as jest.Mock).mockRejectedValue(genericError);

      // Act & Assert - Generic Error
      try {
        await authController.signup(mockReq as Request, mockRes as Response, mockNext);
      } catch (error) {
        expect(error).toEqual(genericError);
      }

      // Verify response not sent on error
      expect(mockRes.status).not.toHaveBeenCalled();
      expect(mockRes.json).not.toHaveBeenCalled();

      // Verify service was called before error
      expect(authService.signup).toHaveBeenCalledWith(signupData, clientIp);
    });
  });
});