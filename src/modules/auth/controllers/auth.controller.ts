/// <reference path="../../../common/types/express.d.ts" />
import { Request, Response } from 'express';
import { asyncHandler } from '@/common/utils/async-handler';
import { getClientIp } from '@/common/utils/ip.utils';
import { authService } from '../services/auth.service';
import { signupService } from '../services/signup.service';
import { verificationService } from '../services/verification.service';
import { passwordService } from '../services/password.service';
import { userService } from '../services/user.service';
import type {
  SignupInput,
  EmailVerificationInput,
  ResendVerificationInput,
  LoginInput,
  RefreshTokenInput,
  ChangePasswordInput,
  PasswordResetRequestInput,
  PasswordResetInput,
} from '../validators/auth.schema';

export class AuthController {
  signup = asyncHandler(async (req: Request<{}, {}, SignupInput>, res: Response) => {
    const ipAddress = getClientIp(req);
    const result = await signupService.signup(req.body, ipAddress);

    res.status(201).json({
      success: true,
      data: result,
    });
  });

  login = asyncHandler(async (req: Request<{}, {}, LoginInput>, res: Response) => {
    const ipAddress = getClientIp(req);
    const userAgent = req.headers['user-agent'];

    const result = await authService.login(req.body, ipAddress, userAgent);

    res.json({
      success: true,
      data: result,
    });
  });

  refresh = asyncHandler(async (req: Request<{}, {}, RefreshTokenInput>, res: Response) => {
    const { refreshToken } = req.body;
    const ipAddress = getClientIp(req);
    const userAgent = req.headers['user-agent'];

    const result = await authService.refresh(refreshToken, ipAddress, userAgent);

    res.json({
      success: true,
      data: result,
    });
  });

  verify = asyncHandler(async (req: Request<{}, {}, EmailVerificationInput>, res: Response) => {
    const { token } = req.body;
    const ipAddress = getClientIp(req);
    const userAgent = req.headers['user-agent'];

    const result = await verificationService.verify(token, ipAddress, userAgent);

    res.json({
      success: true,
      data: result,
    });
  });

  resendVerification = asyncHandler(
    async (req: Request<{}, {}, ResendVerificationInput>, res: Response) => {
      const ipAddress = getClientIp(req);
      const { email } = req.body;

      await verificationService.resendVerification(email, ipAddress);

      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: 'If an account exists with this email, a verification link has been sent.',
      });
    },
  );

  logout = asyncHandler(async (req: Request, res: Response) => {
    // req.user is guaranteed to exist by authenticate middleware
    const { userId, sessionId } = req.user!;
    const ipAddress = getClientIp(req);

    await authService.logout(userId, sessionId, ipAddress);

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  });

  logoutAll = asyncHandler(async (req: Request, res: Response) => {
    // req.user is guaranteed to exist by authenticate middleware
    const { userId } = req.user!;
    const ipAddress = getClientIp(req);

    await authService.logoutAll(userId, ipAddress);

    res.json({
      success: true,
      message: 'Logged out from all devices successfully',
    });
  });

  changePassword = asyncHandler(
    async (req: Request<{}, {}, ChangePasswordInput>, res: Response) => {
      // req.user is guaranteed to exist by authenticate middleware
      const { userId } = req.user!;
      const ipAddress = getClientIp(req);
      const { currentPassword, newPassword, logoutAllDevices } = req.body;

      await passwordService.changePassword({
        userId,
        currentPassword,
        newPassword,
        logoutAllDevices,
        ipAddress,
      });

      res.json({
        success: true,
        message: logoutAllDevices
          ? 'Password changed successfully. You have been logged out from all devices.'
          : 'Password changed successfully.',
      });
    },
  );

  forgotPassword = asyncHandler(
    async (req: Request<{}, {}, PasswordResetRequestInput>, res: Response) => {
      const ipAddress = getClientIp(req);
      const { email } = req.body;

      await passwordService.forgotPassword({
        email,
        ipAddress,
      });

      // Always return success to prevent email enumeration
      res.json({
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent.',
      });
    },
  );

  resetPassword = asyncHandler(async (req: Request<{}, {}, PasswordResetInput>, res: Response) => {
    const ipAddress = getClientIp(req);
    const { token, newPassword } = req.body;

    await passwordService.resetPassword({
      token,
      newPassword,
      ipAddress,
    });

    res.json({
      success: true,
      message: 'Password reset successfully. Please login with your new password.',
    });
  });

  me = asyncHandler(async (req: Request, res: Response) => {
    // req.user is guaranteed to exist by authenticate middleware
    const { userId } = req.user!;

    const userData = await userService.getCurrentUser(userId);

    res.json({
      success: true,
      data: userData,
    });
  });
}

export const authController = new AuthController();
