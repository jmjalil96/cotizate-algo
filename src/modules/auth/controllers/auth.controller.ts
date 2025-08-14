import { Request, Response } from 'express';
import { asyncHandler } from '@/common/utils/async-handler';
import { getClientIp } from '@/common/utils/ip.utils';
import { authService } from '../services/auth.service';
import type { SignupInput, EmailVerificationInput } from '../validators/auth.schema';

export class AuthController {
  signup = asyncHandler(async (req: Request<{}, {}, SignupInput>, res: Response) => {
    const ipAddress = getClientIp(req);
    const result = await authService.signup(req.body, ipAddress);
    
    res.status(201).json({
      success: true,
      data: result,
    });
  });

  verify = asyncHandler(async (req: Request<{}, {}, EmailVerificationInput>, res: Response) => {
    const { token } = req.body;
    const ipAddress = getClientIp(req);
    const userAgent = req.headers['user-agent'];
    
    const result = await authService.verify(token, ipAddress, userAgent);
    
    res.json({
      success: true,
      data: result,
    });
  });
}

export const authController = new AuthController();