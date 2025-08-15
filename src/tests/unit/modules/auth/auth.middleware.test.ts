import { Request, Response, NextFunction } from 'express';
import {
  authenticate,
  authenticateWithSession,
  authenticateOptional,
} from '@/modules/auth/middlewares/auth.middleware';
import { extractBearerToken, verifyAccessToken } from '@/modules/auth/utils/jwt.utils';
import { sessionService } from '@/modules/auth/services/session.service';
import { UnauthorizedError } from '@/common/exceptions/app.error';

// Mock dependencies
jest.mock('@/modules/auth/utils/jwt.utils', () => ({
  extractBearerToken: jest.fn(),
  verifyAccessToken: jest.fn(),
}));

jest.mock('@/modules/auth/services/session.service', () => ({
  sessionService: {
    getValidSession: jest.fn(),
  },
}));

jest.mock('@/common/utils/async-handler', () => ({
  asyncHandler: (fn: any) => fn,
}));

describe('Auth Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      headers: {
        authorization: 'Bearer test-token',
      },
      user: undefined,
    };
    mockRes = {};
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('authenticate (JWT-only)', () => {
    const mockDecoded = {
      userId: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
      sessionId: 'session-123',
    };

    it('should authenticate with valid token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(mockDecoded);

      const middleware = authenticate();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(extractBearerToken).toHaveBeenCalledWith('Bearer test-token');
      expect(verifyAccessToken).toHaveBeenCalledWith('test-token');
      expect(mockReq.user).toEqual({
        userId: mockDecoded.userId,
        email: mockDecoded.email,
        organizationId: mockDecoded.organizationId,
        sessionId: mockDecoded.sessionId,
      });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should throw error when no token provided', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue(null);

      const middleware = authenticate();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'No authentication token provided',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error for expired token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Token has expired');
      });

      const middleware = authenticate();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Authentication token has expired',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error for invalid token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const middleware = authenticate();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Invalid authentication token',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw generic error for other failures', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Some other error');
      });

      const middleware = authenticate();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Authentication failed',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('authenticateWithSession (JWT + Session)', () => {
    const mockDecoded = {
      userId: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
      sessionId: 'session-123',
    };

    const mockSession = {
      id: 'session-123',
      userId: 'user-123',
      isActive: true,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    };

    it('should authenticate with valid token and session', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(mockDecoded);
      (sessionService.getValidSession as jest.Mock).mockResolvedValue(mockSession);

      const middleware = authenticateWithSession();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(extractBearerToken).toHaveBeenCalledWith('Bearer test-token');
      expect(verifyAccessToken).toHaveBeenCalledWith('test-token');
      expect(sessionService.getValidSession).toHaveBeenCalledWith('session-123');
      expect(mockReq.user).toEqual({
        userId: mockDecoded.userId,
        email: mockDecoded.email,
        organizationId: mockDecoded.organizationId,
        sessionId: mockDecoded.sessionId,
      });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should throw error when no token provided', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue(null);

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'No authentication token provided',
      );

      expect(sessionService.getValidSession).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error when JWT has no session ID', async () => {
      const decodedWithoutSession = {
        ...mockDecoded,
        sessionId: undefined,
      };
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(decodedWithoutSession);

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Session validation required for this operation',
      );

      expect(sessionService.getValidSession).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error when session is invalid', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(mockDecoded);
      (sessionService.getValidSession as jest.Mock).mockRejectedValue(
        new UnauthorizedError('Session expired'),
      );

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Session has been terminated or expired',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error when session user mismatch', async () => {
      const mismatchSession = {
        ...mockSession,
        userId: 'different-user',
      };
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(mockDecoded);
      (sessionService.getValidSession as jest.Mock).mockResolvedValue(mismatchSession);

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      // Due to nested try-catch in middleware, session mismatch gets caught and converted
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Session has been terminated or expired',
      );

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error for expired token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Token has expired');
      });

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Authentication token has expired',
      );

      expect(sessionService.getValidSession).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should throw error for invalid token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const middleware = authenticateWithSession();

      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(middleware(mockReq as Request, mockRes as Response, mockNext)).rejects.toThrow(
        'Invalid authentication token',
      );

      expect(sessionService.getValidSession).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('authenticateOptional', () => {
    const mockDecoded = {
      userId: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
      sessionId: 'session-123',
    };

    it('should authenticate with valid token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockReturnValue(mockDecoded);

      const middleware = authenticateOptional();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(extractBearerToken).toHaveBeenCalledWith('Bearer test-token');
      expect(verifyAccessToken).toHaveBeenCalledWith('test-token');
      expect(mockReq.user).toEqual({
        userId: mockDecoded.userId,
        email: mockDecoded.email,
        organizationId: mockDecoded.organizationId,
        sessionId: mockDecoded.sessionId,
      });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when no token', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue(null);

      const middleware = authenticateOptional();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(verifyAccessToken).not.toHaveBeenCalled();
      expect(mockReq.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when token is invalid', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      const middleware = authenticateOptional();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(verifyAccessToken).toHaveBeenCalledWith('test-token');
      expect(mockReq.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should continue without authentication when token is expired', async () => {
      (extractBearerToken as jest.Mock).mockReturnValue('test-token');
      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Token has expired');
      });

      const middleware = authenticateOptional();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(verifyAccessToken).toHaveBeenCalledWith('test-token');
      expect(mockReq.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });
  });
});
