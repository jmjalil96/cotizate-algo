import { prisma } from '@/core/database/prisma.client';
import { UnauthorizedError, ValidationError, NotFoundError } from '@/common/exceptions/app.error';
import {
  hashPassword,
  verifyPassword,
  checkPasswordHistory,
  addPasswordToHistory,
} from '../utils/password.utils';
import { generateResetToken, hashToken } from '../utils/token.utils';
import { sendPasswordResetEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { sessionService } from './session.service';
import { logger } from '@/common/utils/logger';

export interface ChangePasswordOptions {
  userId: string;
  currentPassword: string;
  newPassword: string;
  logoutAllDevices?: boolean;
  ipAddress?: string;
}

export interface ForgotPasswordOptions {
  email: string;
  ipAddress?: string;
}

export interface ResetPasswordOptions {
  token: string;
  newPassword: string;
  ipAddress?: string;
}

export class PasswordService {
  /**
   * Change user's password
   * Requires current password verification for security
   */
  async changePassword(options: ChangePasswordOptions): Promise<void> {
    const { userId, currentPassword, newPassword, logoutAllDevices = false, ipAddress } = options;

    // Get user with current password hash
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        passwordHash: true,
        status: true,
      },
    });

    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    // Check if account is active
    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedError('Account is not active');
    }

    // Verify current password
    const isCurrentPasswordValid = await verifyPassword(currentPassword, user.passwordHash);
    if (!isCurrentPasswordValid) {
      // Log failed attempt for security monitoring
      await auditService.logAction({
        userId,
        action: 'password.change.failed',
        resource: 'password',
        details: {
          reason: 'invalid_current_password',
        },
        ipAddress,
      });

      throw new UnauthorizedError('Current password is incorrect');
    }

    // Check if new password is same as current
    const isSamePassword = await verifyPassword(newPassword, user.passwordHash);
    if (isSamePassword) {
      throw new ValidationError('New password must be different from current password');
    }

    // Check password history (prevent reuse of last 5 passwords)
    const isNotInHistory = await checkPasswordHistory(userId, newPassword);
    if (!isNotInHistory) {
      throw new ValidationError(
        'This password has been used recently. Please choose a different password',
      );
    }

    // Hash the new password
    const newPasswordHash = await hashPassword(newPassword);

    // Update password in transaction
    await prisma.$transaction(async (tx) => {
      // Add current password to history before changing
      await addPasswordToHistory(userId, user.passwordHash, tx);

      // Update user's password
      await tx.user.update({
        where: { id: userId },
        data: {
          passwordHash: newPasswordHash,
          // Reset failed login attempts since password was successfully changed
          failedLoginCount: 0,
          lockedUntil: null,
        },
      });

      // Optionally invalidate all sessions and refresh tokens
      if (logoutAllDevices) {
        // Deactivate all sessions
        await sessionService.deactivateUserSessions(userId, tx);

        // Revoke all refresh tokens
        await sessionService.revokeUserRefreshTokens(userId, tx);

        // Log logout from all devices
        await auditService.logAction(
          {
            userId,
            action: 'auth.logout.all',
            resource: 'auth',
            details: {
              reason: 'password_changed',
            },
            ipAddress,
          },
          tx,
        );
      }

      // Log successful password change
      await auditService.logAction(
        {
          userId,
          action: 'password.change.success',
          resource: 'password',
          details: {
            logoutAllDevices,
          },
          ipAddress,
        },
        tx,
      );
    });
  }

  /**
   * Request password reset
   * Generates a token and sends reset email
   */
  async forgotPassword(options: ForgotPasswordOptions): Promise<void> {
    const { email, ipAddress } = options;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        profile: true,
      },
    });

    // Always respond with success to prevent email enumeration
    // But only process if user exists and is active
    if (!user || user.status !== 'ACTIVE') {
      logger.warn(
        {
          email,
          userExists: !!user,
          userStatus: user?.status,
        },
        'Password reset requested for invalid user',
      );

      // Still log the attempt for security monitoring
      if (user) {
        await auditService.logAction({
          userId: user.id,
          action: 'password.reset.request.failed',
          resource: 'password',
          details: {
            reason: 'account_not_active',
          },
          ipAddress,
        });
      }

      // Return without error to prevent enumeration
      return;
    }

    // Check if there's a recent unexpired token
    const existingToken = await prisma.passwordReset.findFirst({
      where: {
        userId: user.id,
        usedAt: null,
        expiresAt: {
          gt: new Date(),
        },
        createdAt: {
          gt: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
        },
      },
    });

    if (existingToken) {
      logger.info(
        {
          userId: user.id,
          email,
        },
        'Recent password reset token already exists, skipping',
      );

      // Still pretend success to prevent timing attacks
      return;
    }

    // Generate reset token
    // IMPORTANT: We generate a random token, hash it for storage, but send the unhashed version in email
    const resetToken = generateResetToken();
    const hashedToken = hashToken(resetToken);

    // Log for development debugging (remove in production)
    if (process.env.NODE_ENV === 'development') {
      logger.debug(
        {
          email: user.email,
          tokenLength: resetToken.length,
          hashedTokenLength: hashedToken.length,
          message:
            'Password reset token generated (unhashed token sent in email, hashed stored in DB)',
        },
        'Password reset token created',
      );
    }

    // Save token to database
    await prisma.passwordReset.create({
      data: {
        userId: user.id,
        email: user.email,
        token: hashedToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    // Send reset email
    await sendPasswordResetEmail(
      {
        email: user.email,
        firstName: user.profile?.firstName || 'User',
      },
      resetToken,
    );

    // Log the action
    await auditService.logAction({
      userId: user.id,
      action: 'password.reset.request.success',
      resource: 'password',
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
      'Password reset email sent',
    );
  }

  /**
   * Reset password with token
   * Validates token and updates password
   *
   * IMPORTANT: The token parameter should be the UNHASHED token from the email,
   * not the hashed token stored in the database. We hash it here to compare.
   */
  async resetPassword(options: ResetPasswordOptions): Promise<void> {
    const { token, newPassword, ipAddress } = options;

    // Hash the incoming token to compare with database
    // The user provides the unhashed token from email, we hash it to match DB storage
    const hashedToken = hashToken(token);

    // Find valid reset token
    const resetToken = await prisma.passwordReset.findUnique({
      where: { token: hashedToken },
      include: {
        user: {
          include: {
            profile: true,
          },
        },
      },
    });

    // Validate token exists
    if (!resetToken) {
      logger.warn(
        {
          tokenHash: hashedToken,
          tokenLength: token.length,
          message:
            'Token not found. Ensure you are using the token from the email, not the hashed one from DB',
        },
        'Invalid password reset token',
      );

      throw new NotFoundError('Invalid or expired reset token');
    }

    // Check if token has been used
    if (resetToken.usedAt) {
      logger.warn(
        {
          userId: resetToken.userId,
          usedAt: resetToken.usedAt,
        },
        'Attempted to use already used reset token',
      );

      await auditService.logAction({
        userId: resetToken.userId,
        action: 'password.reset.failed',
        resource: 'password',
        details: {
          reason: 'token_already_used',
        },
        ipAddress,
      });

      throw new ValidationError('This reset token has already been used');
    }

    // Check if token has expired
    if (resetToken.expiresAt < new Date()) {
      logger.warn(
        {
          userId: resetToken.userId,
          expiresAt: resetToken.expiresAt,
        },
        'Attempted to use expired reset token',
      );

      await auditService.logAction({
        userId: resetToken.userId,
        action: 'password.reset.failed',
        resource: 'password',
        details: {
          reason: 'token_expired',
        },
        ipAddress,
      });

      throw new ValidationError('This reset token has expired');
    }

    // Check if user is active
    if (resetToken.user.status !== 'ACTIVE') {
      await auditService.logAction({
        userId: resetToken.userId,
        action: 'password.reset.failed',
        resource: 'password',
        details: {
          reason: 'account_not_active',
        },
        ipAddress,
      });

      throw new UnauthorizedError('Account is not active');
    }

    // Check password history
    const isNotInHistory = await checkPasswordHistory(resetToken.userId, newPassword);
    if (!isNotInHistory) {
      await auditService.logAction({
        userId: resetToken.userId,
        action: 'password.reset.failed',
        resource: 'password',
        details: {
          reason: 'password_in_history',
        },
        ipAddress,
      });

      throw new ValidationError(
        'This password has been used recently. Please choose a different password',
      );
    }

    // Hash the new password
    const newPasswordHash = await hashPassword(newPassword);

    // Update password in transaction
    await prisma.$transaction(async (tx) => {
      // Add current password to history before changing
      await addPasswordToHistory(resetToken.userId, resetToken.user.passwordHash, tx);

      // Update user's password
      await tx.user.update({
        where: { id: resetToken.userId },
        data: {
          passwordHash: newPasswordHash,
          // Reset security fields
          failedLoginCount: 0,
          lockedUntil: null,
        },
      });

      // Mark token as used
      await tx.passwordReset.update({
        where: { id: resetToken.id },
        data: {
          usedAt: new Date(),
        },
      });

      // Invalidate all sessions and refresh tokens for security
      await sessionService.deactivateUserSessions(resetToken.userId, tx);
      await sessionService.revokeUserRefreshTokens(resetToken.userId, tx);

      // Log successful reset
      await auditService.logAction(
        {
          userId: resetToken.userId,
          action: 'password.reset.success',
          resource: 'password',
          details: {
            tokenId: resetToken.id,
          },
          ipAddress,
        },
        tx,
      );

      // Log logout from all devices
      await auditService.logAction(
        {
          userId: resetToken.userId,
          action: 'auth.logout.all',
          resource: 'auth',
          details: {
            reason: 'password_reset',
          },
          ipAddress,
        },
        tx,
      );
    });

    logger.info(
      {
        userId: resetToken.userId,
        email: resetToken.user.email,
      },
      'Password reset successful',
    );
  }
}

export const passwordService = new PasswordService();
