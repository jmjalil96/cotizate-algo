import { z } from 'zod';

// UUID validation
export const uuidSchema = z.string().uuid('Invalid ID format');

// Email validation
export const emailSchema = z.string().email('Invalid email format').toLowerCase().trim();

// Password validation
export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(100, 'Password must be less than 100 characters')
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  );

// Pagination schemas
export const paginationSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc'),
});

// Date range schemas
export const dateRangeSchema = z
  .object({
    startDate: z.coerce.date().optional(),
    endDate: z.coerce.date().optional(),
  })
  .refine(
    (data) => {
      if (data.startDate && data.endDate) {
        return data.startDate <= data.endDate;
      }
      return true;
    },
    {
      message: 'Start date must be before or equal to end date',
    },
  );

// Search schema
export const searchSchema = z.object({
  q: z.string().min(1).max(100).optional(),
});

// ID params schema
export const idParamSchema = z.object({
  id: uuidSchema,
});

// Common response schemas
export const successResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  data: z.any().optional(),
});

export const errorResponseSchema = z.object({
  error: z.object({
    message: z.string(),
    statusCode: z.number(),
    details: z.any().optional(),
  }),
});

// Utility function to make all fields optional (for PATCH requests)
export function partialSchema<T extends z.ZodObject<any>>(schema: T) {
  return schema.partial();
}
