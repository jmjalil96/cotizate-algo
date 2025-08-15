import { prisma } from '@/core/database/prisma.client';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { logger } from '@/common/utils/logger';
import { generateVerificationToken } from '../utils/token.utils';
import { generateAccessToken } from '../utils/jwt.utils';
import { sendVerificationEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { sessionService } from './session.service';
import type { EmailVerificationInput } from '../validators/auth.schema';

export class VerificationService {
  /**
   * Resend email verification for pending users
   * Prevents spam by checking for recent tokens
   */
  async resendVerification(email: string, ipAddress?: string) {
    // Find user by email (case-insensitive)
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        profile: true,
      },
    });

    // Always respond with success to prevent email enumeration
    // But only process if user exists and is pending verification
    if (!user || user.status !== 'PENDING') {
      logger.warn(
        {
          email,
          userExists: !!user,
          userStatus: user?.status,
        },
        'Resend verification requested for invalid user',
      );

      // Still log the attempt for security monitoring if user exists
      if (user) {
        await auditService.logAction({
          userId: user.id,
          action: 'auth.verification.resend.failed',
          resource: 'auth',
          details: {
            reason: user.emailVerified ? 'already_verified' : 'invalid_status',
          },
          ipAddress,
        });
      }

      // Return without error to prevent enumeration
      return;
    }

    // Check if there's a recent unexpired token (prevent spam)
    const recentToken = await prisma.emailVerification.findFirst({
      where: {
        userId: user.id,
        expiresAt: {
          gt: new Date(),
        },
        createdAt: {
          gt: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
        },
      },
    });

    if (recentToken) {
      logger.info(
        {
          userId: user.id,
          email,
        },
        'Recent verification token already exists, skipping',
      );

      // Still pretend success to prevent timing attacks
      return;
    }

    // Generate new verification token
    const verificationToken = generateVerificationToken();

    // Create new email verification record
    await prisma.emailVerification.create({
      data: {
        userId: user.id,
        email: user.email,
        token: verificationToken,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      },
    });

    // Send verification email
    await sendVerificationEmail(
      {
        email: user.email,
        firstName: user.profile?.firstName || 'User',
      },
      verificationToken,
    );

    // Log the action
    await auditService.logAction({
      userId: user.id,
      action: 'auth.verification.resend.success',
      resource: 'auth',
      details: {
        email,
      },
      ipAddress,
    });

    logger.info(
      {
        userId: user.id,
        email,
      },
      'Verification email resent',
    );
  }

  /**
   * Verify email address with token
   * Activates user account and creates initial session
   */
  async verify(token: string, ipAddress?: string, userAgent?: string) {
    // Find the email verification token
    const emailVerification = await prisma.emailVerification.findUnique({
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

    if (!emailVerification) {
      throw new NotFoundError('Invalid or expired verification token');
    }

    // Check if token is expired
    if (emailVerification.expiresAt < new Date()) {
      throw new UnauthorizedError('Verification token has expired');
    }

    const { user } = emailVerification;

    // Get the user's organization (first one, since they just signed up)
    const organizationUser = user.organizationUsers[0];
    if (!organizationUser) {
      throw new NotFoundError('Organization not found');
    }

    // Start transaction
    const result = await prisma.$transaction(async (tx) => {
      // Update user status to ACTIVE and set emailVerified
      const updatedUser = await tx.user.update({
        where: { id: user.id },
        data: {
          status: 'ACTIVE',
          emailVerified: true,
          emailVerifiedAt: new Date(),
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

      // Delete the email verification token
      await tx.emailVerification.delete({
        where: { id: emailVerification.id },
      });

      // Log audit event for email verification
      await auditService.logAction(
        {
          userId: user.id,
          organizationId: organizationUser.organizationId,
          action: 'user.email_verified',
          resource: 'user',
          resourceId: user.id,
          details: {
            email: user.email,
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
}

export const verificationService = new VerificationService();
