import { Application } from 'express';
import { Server } from 'http';
import { prisma } from './database/prisma.client';
import { logger } from '../common/utils/logger';

export async function startServer(app: Application, port: number | string): Promise<Server> {
  await prisma.$connect();
  logger.info('Database connected');

  const server = app.listen(port, () => {
    logger.info({ port }, `Server is running on port ${port}`);
  });

  // Enable keep-alive timeout
  server.keepAliveTimeout = 65000; // 65 seconds
  server.headersTimeout = 66000; // 66 seconds

  return server;
}
