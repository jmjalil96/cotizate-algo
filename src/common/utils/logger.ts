import pino from 'pino';
import { env } from '../../core/config/env';

const isDevelopment = env.NODE_ENV === 'development';

export const logger = pino({
  level: isDevelopment ? 'debug' : 'info',
  transport: isDevelopment
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          ignore: 'pid,hostname',
          translateTime: 'SYS:standard',
        },
      }
    : undefined,
  base: {
    env: env.NODE_ENV,
  },
  redact: ['req.headers.authorization', 'req.headers.cookie'],
});

export default logger;
