import { Request, Response } from 'express';
import { prisma } from '../../core/database/prisma.client';
import { asyncHandler } from '../utils/async-handler';

export const healthCheck = (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
};

export const readinessCheck = asyncHandler(async (_req: Request, res: Response) => {
  const checks = {
    database: false,
  };

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.database = true;
  } catch {
    checks.database = false;
  }

  const isReady = Object.values(checks).every((check) => check === true);

  res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'not ready',
    checks,
    timestamp: new Date().toISOString(),
  });
});
