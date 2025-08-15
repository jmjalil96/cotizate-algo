import bcrypt from 'bcrypt';
import { z } from 'zod';
import { prisma } from '@/core/database/prisma.client';
import { Prisma } from '@prisma/client';

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const PASSWORD_HISTORY_LIMIT = 5;

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

/**
 * Hash a plain text password
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Verify a plain text password against a hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Validate password strength
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  errors: string[];
} {
  const result = passwordSchema.safeParse(password);

  if (result.success) {
    return { isValid: true, errors: [] };
  }

  return {
    isValid: false,
    errors: result.error.issues.map((issue) => issue.message),
  };
}

/**
 * Generate a temporary password for admin resets
 */
export function generateTemporaryPassword(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';

  for (let i = 0; i < 16; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return password;
}

/**
 * Check if password was recently used
 */
export async function checkPasswordHistory(
  userId: string,
  newPassword: string,
  tx?: Prisma.TransactionClient,
): Promise<boolean> {
  const client = tx || prisma;
  const passwordHistory = await client.passwordHistory.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: PASSWORD_HISTORY_LIMIT,
  });

  for (const history of passwordHistory) {
    const isDuplicate = await bcrypt.compare(newPassword, history.passwordHash);
    if (isDuplicate) {
      return false;
    }
  }

  return true;
}

/**
 * Add password to history
 */
export async function addPasswordToHistory(
  userId: string,
  passwordHash: string,
  tx?: Prisma.TransactionClient,
): Promise<void> {
  const client = tx || prisma;

  await client.passwordHistory.create({
    data: {
      userId,
      passwordHash,
    },
  });

  const allHistory = await client.passwordHistory.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  });

  if (allHistory.length > PASSWORD_HISTORY_LIMIT) {
    const idsToDelete = allHistory.slice(PASSWORD_HISTORY_LIMIT).map((h) => h.id);

    await client.passwordHistory.deleteMany({
      where: {
        id: { in: idsToDelete },
      },
    });
  }
}

/**
 * Calculate password entropy (bits)
 */
export function calculatePasswordEntropy(password: string): number {
  const charsets = [
    { regex: /[a-z]/, size: 26 },
    { regex: /[A-Z]/, size: 26 },
    { regex: /[0-9]/, size: 10 },
    { regex: /[^A-Za-z0-9]/, size: 32 },
  ];

  let poolSize = 0;
  for (const charset of charsets) {
    if (charset.regex.test(password)) {
      poolSize += charset.size;
    }
  }

  const entropy = password.length * Math.log2(poolSize);
  return Math.round(entropy);
}

/**
 * Get password strength level
 */
export function getPasswordStrength(password: string): {
  score: number;
  level: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  feedback: string[];
} {
  const entropy = calculatePasswordEntropy(password);
  const feedback: string[] = [];
  let score = 0;
  let level: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (password.length < 8) {
    feedback.push('Use at least 8 characters');
  }
  if (!/[A-Z]/.test(password)) {
    feedback.push('Include uppercase letters');
  }
  if (!/[a-z]/.test(password)) {
    feedback.push('Include lowercase letters');
  }
  if (!/[0-9]/.test(password)) {
    feedback.push('Include numbers');
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    feedback.push('Include special characters');
  }

  if (entropy < 30) {
    level = 'weak';
  } else if (entropy < 40) {
    level = 'fair';
  } else if (entropy < 50) {
    level = 'good';
  } else if (entropy < 60) {
    level = 'strong';
  } else {
    level = 'very-strong';
  }

  return { score, level, feedback };
}
