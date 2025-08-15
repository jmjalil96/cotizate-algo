import { prisma } from '@/core/database/prisma.client';
import { Prisma } from '@prisma/client';
import { env } from '@/core/config/env';
import { generateRefreshToken } from '../utils/jwt.utils';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';

export interface CreateSessionOptions {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  tx?: Prisma.TransactionClient;
}

export interface CreateRefreshTokenOptions {
  userId: string;
  sessionId: string;
  deviceId?: string;
  ipAddress?: string;
  userAgent?: string;
  tx?: Prisma.TransactionClient;
}

export class SessionService {
  /**
   * Create a new session for a user
   */
  async createSession(options: CreateSessionOptions) {
    const { userId, ipAddress, userAgent, tx } = options;
    const client = tx || prisma;

    // Calculate session expiry (8 hours by default - a work day)
    const sessionDuration = this.parseDuration(env.SESSION_EXPIRES_IN || '8h');
    const expiresAt = new Date(Date.now() + sessionDuration);

    const session = await client.session.create({
      data: {
        userId,
        ipAddress,
        userAgent,
        expiresAt,
        isActive: true,
      },
    });

    return session;
  }

  /**
   * Create a refresh token for a session
   */
  async createRefreshToken(options: CreateRefreshTokenOptions) {
    const { userId, sessionId, deviceId, ipAddress, userAgent, tx } = options;
    const client = tx || prisma;

    // Generate refresh token (UUID)
    const refreshToken = generateRefreshToken();

    // Calculate refresh token expiry (same as session - 8 hours)
    const refreshDuration = this.parseDuration(env.REFRESH_TOKEN_EXPIRES_IN || '8h');
    const expiresAt = new Date(Date.now() + refreshDuration);

    const token = await client.refreshToken.create({
      data: {
        userId,
        sessionId, // Link to session!
        token: refreshToken,
        deviceId,
        ipAddress,
        userAgent,
        expiresAt,
      },
    });

    return token;
  }

  /**
   * Get a valid refresh token with session validation
   */
  async getValidRefreshToken(token: string) {
    const refreshToken = await prisma.refreshToken.findUnique({
      where: { token },
      include: {
        session: true, // Include session for validation
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

    if (!refreshToken) {
      throw new NotFoundError('Invalid refresh token');
    }

    if (refreshToken.isRevoked) {
      throw new UnauthorizedError('Refresh token has been revoked');
    }

    if (refreshToken.expiresAt < new Date()) {
      throw new UnauthorizedError('Refresh token has expired');
    }

    // Check if session is still active
    if (!refreshToken.session || !refreshToken.session.isActive) {
      throw new UnauthorizedError('Session has been terminated');
    }

    if (refreshToken.session.expiresAt < new Date()) {
      throw new UnauthorizedError('Session has expired');
    }

    return refreshToken;
  }

  /**
   * Revoke a refresh token
   */
  async revokeRefreshToken(token: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;

    const refreshToken = await client.refreshToken.update({
      where: { token },
      data: { isRevoked: true },
    });

    return refreshToken;
  }

  /**
   * Revoke all refresh tokens in a family (for rotation security)
   */
  async revokeRefreshTokenFamily(family: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;

    await client.refreshToken.updateMany({
      where: { family },
      data: { isRevoked: true },
    });
  }

  /**
   * Rotate refresh token (for security during refresh)
   */
  async rotateRefreshToken(
    oldToken: string,
    userId: string,
    sessionId: string, // Add sessionId parameter
    family: string,
    ipAddress?: string,
    userAgent?: string,
    deviceId?: string,
    tx?: Prisma.TransactionClient,
  ) {
    const client = tx || prisma;

    // Revoke the old token
    await client.refreshToken.update({
      where: { token: oldToken },
      data: { isRevoked: true },
    });

    // Generate new refresh token
    const newToken = generateRefreshToken();

    // Calculate refresh token expiry (8 hours - same as session)
    const refreshDuration = this.parseDuration(env.REFRESH_TOKEN_EXPIRES_IN || '8h');
    const expiresAt = new Date(Date.now() + refreshDuration);

    // Create new token with same family and session
    const refreshToken = await client.refreshToken.create({
      data: {
        userId,
        sessionId, // Keep same session ID!
        token: newToken,
        family, // SAME family for rotation tracking
        deviceId,
        ipAddress,
        userAgent,
        expiresAt,
      },
    });

    return refreshToken;
  }

  /**
   * Get valid session by ID
   */
  async getValidSession(sessionId: string) {
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
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

    if (!session) {
      throw new NotFoundError('Invalid session');
    }

    if (!session.isActive) {
      throw new UnauthorizedError('Session has been terminated');
    }

    if (session.expiresAt < new Date()) {
      // Mark session as inactive
      await prisma.session.update({
        where: { id: session.id },
        data: { isActive: false },
      });
      throw new UnauthorizedError('Session has expired');
    }

    return session;
  }

  /**
   * Deactivate a session and its refresh tokens
   */
  async deactivateSession(sessionId: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;

    // Mark session as inactive
    await client.session.update({
      where: { id: sessionId },
      data: { isActive: false },
    });

    // Revoke all refresh tokens for this session
    await client.refreshToken.updateMany({
      where: {
        sessionId,
        isRevoked: false,
      },
      data: { isRevoked: true },
    });
  }

  /**
   * Deactivate all sessions for a user
   */
  async deactivateUserSessions(userId: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;

    await client.session.updateMany({
      where: {
        userId,
        isActive: true,
      },
      data: { isActive: false },
    });
  }

  /**
   * Revoke all refresh tokens for a user
   */
  async revokeUserRefreshTokens(userId: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;

    await client.refreshToken.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: { isRevoked: true },
    });
  }

  /**
   * Parse duration string to milliseconds
   */
  private parseDuration(duration: string): number {
    const units: { [key: string]: number } = {
      ms: 1,
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
      w: 7 * 24 * 60 * 60 * 1000,
    };

    const match = duration.match(/^(\d+)([a-z]+)$/i);
    if (!match) {
      // Default to 24 hours if parsing fails
      return 24 * 60 * 60 * 1000;
    }

    const value = parseInt(match[1], 10);
    const unit = match[2].toLowerCase();

    return value * (units[unit] || units.h);
  }

  /**
   * Clean up expired sessions and tokens
   */
  async cleanupExpired() {
    const now = new Date();

    // Clean up expired sessions
    await prisma.session.updateMany({
      where: {
        expiresAt: { lt: now },
        isActive: true,
      },
      data: { isActive: false },
    });

    // Delete very old expired sessions (older than 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    await prisma.session.deleteMany({
      where: {
        expiresAt: { lt: thirtyDaysAgo },
      },
    });

    // Delete expired refresh tokens older than 30 days
    await prisma.refreshToken.deleteMany({
      where: {
        expiresAt: { lt: thirtyDaysAgo },
      },
    });
  }
}

export const sessionService = new SessionService();
