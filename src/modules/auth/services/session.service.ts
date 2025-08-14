import { prisma } from '@/core/database/prisma.client';
import { Prisma } from '@prisma/client';
import { env } from '@/core/config/env';
import { generateSessionToken } from '../utils/token.utils';
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
    
    // Generate unique session token
    const sessionToken = generateSessionToken();
    
    // Calculate session expiry (24 hours by default)
    const sessionDuration = this.parseDuration(env.SESSION_EXPIRES_IN || '24h');
    const expiresAt = new Date(Date.now() + sessionDuration);
    
    const session = await client.session.create({
      data: {
        userId,
        token: sessionToken,
        ipAddress,
        userAgent,
        expiresAt,
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
    
    // Calculate refresh token expiry (7 days by default)
    const refreshDuration = this.parseDuration(env.REFRESH_TOKEN_EXPIRES_IN || '7d');
    const expiresAt = new Date(Date.now() + refreshDuration);
    
    const token = await client.refreshToken.create({
      data: {
        userId,
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
   * Get a valid refresh token
   */
  async getValidRefreshToken(token: string) {
    const refreshToken = await prisma.refreshToken.findUnique({
      where: { token },
      include: {
        user: {
          include: {
            profile: true,
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
   * Get valid session by token
   */
  async getValidSession(token: string) {
    const session = await prisma.session.findUnique({
      where: { token },
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
    
    if (session.isExpired) {
      throw new UnauthorizedError('Session has expired');
    }
    
    if (session.expiresAt < new Date()) {
      // Mark session as expired
      await prisma.session.update({
        where: { id: session.id },
        data: { isExpired: true },
      });
      throw new UnauthorizedError('Session has expired');
    }
    
    return session;
  }
  
  /**
   * Expire a session
   */
  async expireSession(sessionId: string, tx?: Prisma.TransactionClient) {
    const client = tx || prisma;
    
    await client.session.update({
      where: { id: sessionId },
      data: { isExpired: true },
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
        isExpired: false,
      },
      data: { isExpired: true },
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