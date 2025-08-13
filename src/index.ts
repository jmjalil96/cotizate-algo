import { env } from './core/config/env';
import { createApp } from './core/app';
import { startServer } from './core/server';
import { setupGracefulShutdown } from './core/shutdown';
import { prisma } from './core/database/prisma.client';
import { logger } from './common/utils/logger';

async function main() {
  try {
    // Create and start the application
    const app = createApp();
    const server = await startServer(app, env.PORT);

    // Setup graceful shutdown
    setupGracefulShutdown(server, {
      timeout: 30000, // 30 seconds timeout
      onShutdown: async () => {
        // Add any custom cleanup here
        logger.info('Performing custom cleanup');
      },
    });

    logger.info(
      {
        nodeVersion: process.version,
        environment: env.NODE_ENV,
        port: env.PORT,
      },
      'Application started successfully',
    );
  } catch (error) {
    logger.fatal(error, 'Fatal error during startup');
    await prisma.$disconnect();
    process.exit(1);
  }
}

// Start the application
main();
