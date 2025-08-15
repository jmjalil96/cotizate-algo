import { prisma } from '@/core/database/prisma.client';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { verifyPassword } from '../utils/password.utils';
import { generateAccessToken } from '../utils/jwt.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { sessionService } from './session.service';
import type { LoginInput } from '../validators/auth.schema';

// Security constants
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const LOGIN_WINDOW = 15 * 60 * 1000; // Reset counter after 15 min of no attempts

export class AuthService {
  /**
   * Authenticate user with email and password
   * Creates session and returns JWT tokens
   */
  async login(data: LoginInput, ipAddress?: string, userAgent?: string) {
    // Find user with all necessary relations
    const user = await prisma.user.findUnique({
      where: { email: data.email },
      include: {
        profile: true,
        organizationUsers: {
          include: {
            organization: true,
            role: true,
          },
        },
      },
    });

    // Generic error for invalid credentials (prevents user enumeration)
    const invalidCredentialsError = new UnauthorizedError('Invalid credentials');

    // If user doesn't exist, throw generic error
    if (!user) {
      // Log the failed attempt for security monitoring
      await auditService.logAction({
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          email: data.email,
          reason: 'user_not_found',
        },
        ipAddress,
      });
      throw invalidCredentialsError;
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const remainingTime = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000 / 60);
      throw new UnauthorizedError(
        `Account temporarily locked. Please try again in ${remainingTime} minutes.`,
      );
    }

    // Check if account is active
    if (user.status !== 'ACTIVE') {
      // Log the failed attempt
      await auditService.logAction({
        userId: user.id,
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          reason: 'account_not_active',
          status: user.status,
        },
        ipAddress,
      });

      if (user.status === 'PENDING') {
        throw new UnauthorizedError('Please verify your email before logging in');
      } else {
        throw new UnauthorizedError('Account is not active');
      }
    }

    // Verify password
    const isValidPassword = await verifyPassword(data.password, user.passwordHash);

    if (!isValidPassword) {
      // Update failed login count
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginCount: user.failedLoginCount + 1,
          // Lock account if max attempts reached
          ...(user.failedLoginCount + 1 >= MAX_LOGIN_ATTEMPTS && {
            lockedUntil: new Date(Date.now() + LOCKOUT_DURATION),
          }),
        },
      });

      // Log failed attempt
      await auditService.logAction({
        userId: user.id,
        action: 'auth.login.failed',
        resource: 'auth',
        details: {
          attempt: updatedUser.failedLoginCount,
          locked: updatedUser.failedLoginCount >= MAX_LOGIN_ATTEMPTS,
        },
        ipAddress,
      });

      // If account just got locked, log that too
      if (updatedUser.failedLoginCount >= MAX_LOGIN_ATTEMPTS) {
        await auditService.logAction({
          userId: user.id,
          action: 'auth.login.locked',
          resource: 'auth',
          details: {
            lockedUntil: updatedUser.lockedUntil,
          },
          ipAddress,
        });
      }

      throw invalidCredentialsError;
    }

    // Get the user's first organization (for now)
    const organizationUser = user.organizationUsers[0];
    if (!organizationUser) {
      throw new NotFoundError('No organization associated with this account');
    }

    // Successful login - reset failed attempts and update login info
    const result = await prisma.$transaction(async (tx) => {
      // Update user login info
      const updatedUser = await tx.user.update({
        where: { id: user.id },
        data: {
          failedLoginCount: 0,
          lockedUntil: null,
          lastLoginAt: new Date(),
          lastLoginIp: ipAddress,
        },
      });

      // Create session (master record)
      const session = await sessionService.createSession({
        userId: user.id,
        ipAddress,
        userAgent,
        tx,
      });

      // Create refresh token linked to session
      const refreshToken = await sessionService.createRefreshToken({
        userId: user.id,
        sessionId: session.id, // Link to session!
        ipAddress,
        userAgent,
        tx,
      });

      // Log successful login
      await auditService.logAction(
        {
          userId: user.id,
          organizationId: organizationUser.organizationId,
          action: 'auth.login.success',
          resource: 'auth',
          details: {
            sessionId: session.id,
          },
          ipAddress,
        },
        tx,
      );

      return {
        user: updatedUser,
        session,
        refreshToken: refreshToken.token,
      };
    });

    // Generate JWT access token with session ID
    const accessToken = generateAccessToken({
      userId: result.user.id,
      email: result.user.email,
      organizationId: organizationUser.organizationId,
      sessionId: result.session.id, // Include session ID in JWT!
    });

    return {
      accessToken,
      refreshToken: result.refreshToken,
      user: {
        id: result.user.id,
        email: result.user.email,
        firstName: user.profile?.firstName,
        lastName: user.profile?.lastName,
      },
      organization: {
        id: organizationUser.organization.id,
        name: organizationUser.organization.name,
        slug: organizationUser.organization.slug,
      },
    };
  }

  /**
   * Refresh access token using refresh token
   * Implements token rotation for security
   */
  async refresh(refreshToken: string, ipAddress?: string, userAgent?: string) {
    // Get valid refresh token with all relations
    const tokenData = await sessionService.getValidRefreshToken(refreshToken);

    if (!tokenData) {
      throw new UnauthorizedError('Invalid or expired refresh token');
    }

    // Get user with organization data
    const user = await prisma.user.findUnique({
      where: { id: tokenData.userId },
      include: {
        profile: true,
        organizationUsers: {
          include: {
            organization: true,
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundError('User not found');
    }

    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedError('Account is not active');
    }

    const organizationUser = user.organizationUsers[0];
    if (!organizationUser) {
      throw new NotFoundError('No organization associated with this account');
    }

    // Rotate the refresh token (create new, revoke old)
    const newRefreshToken = await sessionService.rotateRefreshToken(
      refreshToken,
      tokenData.userId,
      tokenData.sessionId,
      tokenData.family,
      ipAddress,
      userAgent,
      tokenData.deviceId || undefined,
    );

    // Generate new JWT access token with session ID from the rotated token
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email,
      organizationId: organizationUser.organizationId,
      sessionId: tokenData.sessionId, // Use session ID from refresh token
    });

    // Log token refresh
    await auditService.logAction({
      userId: user.id,
      organizationId: organizationUser.organizationId,
      action: 'auth.token.refresh',
      resource: 'auth',
      details: {
        sessionId: tokenData.sessionId,
      },
      ipAddress,
    });

    return {
      accessToken,
      refreshToken: newRefreshToken.token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.profile?.firstName,
        lastName: user.profile?.lastName,
      },
      organization: {
        id: organizationUser.organization.id,
        name: organizationUser.organization.name,
        slug: organizationUser.organization.slug,
      },
    };
  }

  /**
   * Handle user logout - deactivate session
   */
  async logout(userId: string, sessionId?: string, ipAddress?: string) {
    await prisma.$transaction(async (tx) => {
      if (sessionId) {
        // Deactivate the specific session and its refresh tokens
        await sessionService.deactivateSession(sessionId, tx);
      } else {
        // If no sessionId provided, deactivate all sessions
        await sessionService.deactivateUserSessions(userId, tx);
      }

      // Log logout event
      await auditService.logAction(
        {
          userId,
          action: 'auth.logout',
          resource: 'auth',
          details: {
            sessionId: sessionId || 'all',
          },
          ipAddress,
        },
        tx,
      );
    });
  }

  /**
   * Logout from all devices - deactivate all sessions
   */
  async logoutAll(userId: string, ipAddress?: string) {
    await prisma.$transaction(async (tx) => {
      // Deactivate all user sessions
      await sessionService.deactivateUserSessions(userId, tx);

      // Revoke all refresh tokens
      await sessionService.revokeUserRefreshTokens(userId, tx);

      // Log logout all event
      await auditService.logAction(
        {
          userId,
          action: 'auth.logout.all',
          resource: 'auth',
          details: {
            reason: 'user_initiated',
          },
          ipAddress,
        },
        tx,
      );
    });
  }
}

export const authService = new AuthService();
