import { Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { ValidationError } from '../exceptions/app.error';

type ValidationTarget = 'body' | 'query' | 'params';

interface ValidationOptions {
  target?: ValidationTarget;
  stripUnknown?: boolean;
}

export function validate<T extends z.ZodSchema>(schema: T, options: ValidationOptions = {}) {
  const { target = 'body', stripUnknown = true } = options;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = req[target];

      // Apply strip() if stripUnknown is true
      const finalSchema = stripUnknown && 'strip' in schema ? (schema as any).strip() : schema;
      const validated = await finalSchema.parseAsync(data);

      // Replace the original data with validated data
      req[target] = validated;

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const formattedErrors = error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));

        const errorMessage = formattedErrors
          .map((err) => `${err.field}: ${err.message}`)
          .join(', ');

        next(new ValidationError(errorMessage));
      } else {
        next(error);
      }
    }
  };
}

// Validate multiple targets at once
export function validateAll(schemas: {
  body?: z.ZodSchema;
  query?: z.ZodSchema;
  params?: z.ZodSchema;
}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const results: Record<string, any> = {};

      if (schemas.body) {
        const bodySchema = 'strip' in schemas.body ? (schemas.body as any).strip() : schemas.body;
        results.body = await bodySchema.parseAsync(req.body);
        req.body = results.body;
      }

      if (schemas.query) {
        const querySchema =
          'strip' in schemas.query ? (schemas.query as any).strip() : schemas.query;
        results.query = await querySchema.parseAsync(req.query);
        req.query = results.query;
      }

      if (schemas.params) {
        const paramsSchema =
          'strip' in schemas.params ? (schemas.params as any).strip() : schemas.params;
        results.params = await paramsSchema.parseAsync(req.params);
        req.params = results.params;
      }

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const formattedErrors = error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));

        const errorMessage = formattedErrors
          .map((err) => `${err.field}: ${err.message}`)
          .join(', ');

        next(new ValidationError(errorMessage));
      } else {
        next(error);
      }
    }
  };
}
