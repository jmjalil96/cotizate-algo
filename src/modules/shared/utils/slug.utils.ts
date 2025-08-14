import slugify from 'slugify';
import { prisma } from '@/core/database/prisma.client';
import { randomInt } from '@/common/utils/crypto.utils';

/**
 * Reserved slugs that cannot be used
 */
const RESERVED_SLUGS = [
  'admin',
  'api',
  'app',
  'auth',
  'blog',
  'dashboard',
  'docs',
  'help',
  'home',
  'login',
  'logout',
  'register',
  'settings',
  'signup',
  'support',
  'www',
  'mail',
  'email',
  'ftp',
  'blog',
  'dev',
  'stage',
  'staging',
  'test',
  'testing',
  'prod',
  'production',
  'static',
  'assets',
  'public',
  'private',
  'about',
  'contact',
  'privacy',
  'terms',
  'legal',
  'security',
  'status',
  'health',
  'metrics',
  'analytics',
  'cdn',
  'media',
  'images',
  'files',
  'downloads',
  'uploads',
];

/**
 * Generate a URL-safe slug from text
 */
export function generateSlug(text: string): string {
  return slugify(text, {
    lower: true,
    strict: true,
    remove: /[*+~.()'"!:@]/g,
  });
}

/**
 * Check if slug is reserved
 */
export function isReservedSlug(slug: string): boolean {
  return RESERVED_SLUGS.includes(slug.toLowerCase());
}

/**
 * Validate slug format
 */
export function validateSlug(slug: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (!slug) {
    errors.push('Slug cannot be empty');
  }
  
  if (slug.length < 3) {
    errors.push('Slug must be at least 3 characters');
  }
  
  if (slug.length > 63) {
    errors.push('Slug must be less than 64 characters');
  }
  
  if (!/^[a-z0-9-]+$/.test(slug)) {
    errors.push('Slug can only contain lowercase letters, numbers, and hyphens');
  }
  
  if (slug.startsWith('-') || slug.endsWith('-')) {
    errors.push('Slug cannot start or end with a hyphen');
  }
  
  if (slug.includes('--')) {
    errors.push('Slug cannot contain consecutive hyphens');
  }
  
  if (isReservedSlug(slug)) {
    errors.push('This slug is reserved and cannot be used');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Ensure slug is unique for organizations
 */
export async function ensureUniqueOrganizationSlug(
  baseSlug: string,
  excludeId?: string
): Promise<string> {
  let slug = baseSlug;
  let counter = 0;
  const maxAttempts = 10;
  
  while (counter < maxAttempts) {
    const existing = await prisma.organization.findFirst({
      where: {
        slug,
        ...(excludeId && { NOT: { id: excludeId } }),
      },
    });
    
    if (!existing) {
      return slug;
    }
    
    counter++;
    slug = `${baseSlug}-${randomInt(1000, 9999)}`;
  }
  
  slug = `${baseSlug}-${Date.now()}`;
  return slug;
}

/**
 * Generate slug from organization name
 */
export async function generateOrganizationSlug(
  name: string,
  excludeId?: string
): Promise<string> {
  const baseSlug = generateSlug(name);
  
  if (isReservedSlug(baseSlug)) {
    const modifiedSlug = `${baseSlug}-org`;
    return ensureUniqueOrganizationSlug(modifiedSlug, excludeId);
  }
  
  return ensureUniqueOrganizationSlug(baseSlug, excludeId);
}

/**
 * Suggest alternative slugs
 */
export async function suggestAlternativeSlugs(
  baseSlug: string,
  count: number = 3
): Promise<string[]> {
  const suggestions: string[] = [];
  const variations = [
    `${baseSlug}-team`,
    `${baseSlug}-org`,
    `${baseSlug}-co`,
    `${baseSlug}-hq`,
    `${baseSlug}-group`,
    `${baseSlug}-${new Date().getFullYear()}`,
  ];
  
  for (const variation of variations) {
    if (suggestions.length >= count) break;
    
    const existing = await prisma.organization.findFirst({
      where: { slug: variation },
    });
    
    if (!existing && !isReservedSlug(variation)) {
      suggestions.push(variation);
    }
  }
  
  while (suggestions.length < count) {
    const randomSuffix = randomInt(100, 999);
    const randomSlug = `${baseSlug}-${randomSuffix}`;
    
    const existing = await prisma.organization.findFirst({
      where: { slug: randomSlug },
    });
    
    if (!existing) {
      suggestions.push(randomSlug);
    }
  }
  
  return suggestions;
}

/**
 * Parse slug to get organization
 */
export async function getOrganizationBySlug(slug: string) {
  return prisma.organization.findUnique({
    where: { slug },
  });
}