import { Server } from 'http';
import { logger } from '../common/utils/logger';
import { prisma } from './database/prisma.client';

interface ShutdownOptions {
  timeout?: number; // Timeout in milliseconds
  server: Server;
  onShutdown?: () => Promise<void>; // Additional cleanup function
}

export class GracefulShutdown {
  private isShuttingDown = false;
  private timeout: number;
  private server: Server;
  private onShutdown?: () => Promise<void>;

  constructor(options: ShutdownOptions) {
    this.timeout = options.timeout || 30000; // Default 30 seconds
    this.server = options.server;
    this.onShutdown = options.onShutdown;
  }

  public registerHandlers(): void {
    // Handle SIGTERM (from Docker, Kubernetes, etc.)
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));

    // Handle SIGINT (Ctrl+C)
    process.on('SIGINT', () => this.shutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.fatal({ error }, 'Uncaught exception');
      this.shutdown('UNCAUGHT_EXCEPTION');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.fatal({ reason, promise }, 'Unhandled promise rejection');
      this.shutdown('UNHANDLED_REJECTION');
    });
  }

  private async shutdown(signal: string): Promise<void> {
    if (this.isShuttingDown) {
      logger.info('Shutdown already in progress');
      return;
    }

    this.isShuttingDown = true;
    logger.info({ signal }, `Graceful shutdown initiated by ${signal}`);

    // Set timeout to force shutdown
    const forceShutdownTimeout = setTimeout(() => {
      logger.error('Graceful shutdown timeout, forcing exit');
      process.exit(1);
    }, this.timeout);

    try {
      // Step 1: Stop accepting new connections
      logger.info('Stopping server from accepting new connections');
      await this.closeServer();

      // Step 2: Close database connections
      logger.info('Closing database connections');
      await prisma.$disconnect();

      // Step 3: Run custom cleanup if provided
      if (this.onShutdown) {
        logger.info('Running custom cleanup');
        await this.onShutdown();
      }

      // Step 4: Clear timeout and exit
      clearTimeout(forceShutdownTimeout);
      logger.info('Graceful shutdown completed successfully');
      process.exit(0);
    } catch (error) {
      clearTimeout(forceShutdownTimeout);
      logger.error({ error }, 'Error during graceful shutdown');
      process.exit(1);
    }
  }

  private closeServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
}

export function setupGracefulShutdown(server: Server, options?: Partial<ShutdownOptions>): void {
  const shutdown = new GracefulShutdown({
    server,
    ...options,
  });

  shutdown.registerHandlers();
}
