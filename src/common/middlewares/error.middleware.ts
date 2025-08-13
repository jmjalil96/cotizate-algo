import { Request, Response, NextFunction } from 'express';
import { AppError } from '../exceptions/app.error';
import { env } from '../../core/config/env';
import { logger } from '../utils/logger';

export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction,
) => {
  let statusCode = 500;
  let message = 'Internal server error';
  let stack: string | undefined;

  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
  } else if (err.name === 'ValidationError') {
    statusCode = 400;
    message = err.message;
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  }

  const logContext = {
    requestId: req.id,
    method: req.method,
    url: req.url,
    statusCode,
    message: err.message,
    stack: err.stack,
    ...(err instanceof AppError && { isOperational: err.isOperational }),
  };

  if (err instanceof AppError && err.isOperational) {
    logger.warn(logContext, 'Operational error');
  } else {
    logger.error(logContext, 'Unexpected error');
  }

  if (env.NODE_ENV === 'development') {
    stack = err.stack;
  } else if (!(err instanceof AppError) || !err.isOperational) {
    message = 'Something went wrong';
  }

  res.status(statusCode).json({
    error: {
      message,
      statusCode,
      requestId: req.id,
      ...(stack && { stack }),
    },
  });
};
