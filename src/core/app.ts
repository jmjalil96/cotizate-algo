import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import swaggerUi from 'swagger-ui-express';
import { errorHandler } from '../common/middlewares/error.middleware';
import { loggingMiddleware } from '../common/middlewares/logging.middleware';
import { requestIdMiddleware } from '../common/middlewares/request-id.middleware';
import { globalRateLimiter } from '../common/middlewares/rate-limit.middleware';
import { NotFoundError } from '../common/exceptions/app.error';
import healthRoutes from '../common/routes/health.routes';
import apiRouter from '../api';
import { env } from './config/env';
import { swaggerSpec } from './config/swagger';

export function createApp(): Application {
  const app = express();

  // Trust proxy (required for correct IPs behind reverse proxies)
  app.set('trust proxy', 1);

  // Request ID (should be very early)
  app.use(requestIdMiddleware);

  // Logging middleware (should be early)
  app.use(loggingMiddleware);

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy:
        env.NODE_ENV === 'production'
          ? {
              directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", 'data:', 'https:'],
              },
            }
          : {
              directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
                imgSrc: ["'self'", 'data:', 'https:'],
              },
            },
    }),
  );

  // CORS configuration
  app.use(
    cors({
      origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN,
      credentials: true,
      optionsSuccessStatus: 200,
      exposedHeaders: ['X-Request-Id'],
    }),
  );

  // Compression middleware
  app.use(
    compression({
      threshold: 1024, // Only compress responses > 1KB
      level: 6, // Default compression level (good balance)
    }),
  );

  // Rate limiting
  app.use(globalRateLimiter);

  // Body parsing with size limits
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // Health routes (outside API versioning)
  app.use(healthRoutes);

  // API documentation (only in development/staging)
  if (env.NODE_ENV !== 'production') {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  }

  // API routes
  app.use('/api', apiRouter);

  app.get('/', (req, res) => {
    res.json({
      message: 'API is running',
      docs: env.NODE_ENV !== 'production' ? '/api-docs' : undefined,
      endpoints: {
        health: '/health',
        api: '/api/v1',
      },
    });
  });

  // 404 handler
  app.use((_req: Request, _res: Response, next: NextFunction) => {
    next(new NotFoundError('Route not found'));
  });

  // Global error handler (must be last)
  app.use(errorHandler);

  return app;
}
