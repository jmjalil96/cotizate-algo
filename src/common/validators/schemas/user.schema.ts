import { z } from 'zod';
import { emailSchema, uuidSchema, paginationSchema } from './common.schema';

// Create user schema
export const createUserSchema = z.object({
  email: emailSchema,
  name: z.string().min(2).max(100).optional(),
  role: z.enum(['USER', 'ADMIN']).default('USER').optional(),
});

// Update user schema
export const updateUserSchema = z
  .object({
    email: emailSchema.optional(),
    name: z.string().min(2).max(100).optional(),
    role: z.enum(['USER', 'ADMIN']).optional(),
  })
  .refine((data) => Object.keys(data).length > 0, {
    message: 'At least one field must be provided for update',
  });

// User query params schema
export const userQuerySchema = paginationSchema.extend({
  email: z.string().optional(),
  name: z.string().optional(),
  role: z.enum(['USER', 'ADMIN']).optional(),
  isActive: z.coerce.boolean().optional(),
});

// User ID param schema
export const userIdParamSchema = z.object({
  userId: uuidSchema,
});

// Bulk user operations schema
export const bulkUserOperationSchema = z.object({
  userIds: z.array(uuidSchema).min(1).max(100),
  operation: z.enum(['activate', 'deactivate', 'delete']),
});

// User response schema (for documentation)
export const userResponseSchema = z.object({
  id: uuidSchema,
  email: emailSchema,
  name: z.string().nullable(),
  role: z.enum(['USER', 'ADMIN']),
  createdAt: z.date(),
  updatedAt: z.date(),
});

// Type exports
export type CreateUserInput = z.infer<typeof createUserSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
export type UserQueryInput = z.infer<typeof userQuerySchema>;
export type UserIdParam = z.infer<typeof userIdParamSchema>;
export type BulkUserOperationInput = z.infer<typeof bulkUserOperationSchema>;
export type UserResponse = z.infer<typeof userResponseSchema>;
