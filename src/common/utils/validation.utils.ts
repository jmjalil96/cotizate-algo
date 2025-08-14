import validator from 'validator';

/**
 * Sanitize email address
 */
export function sanitizeEmail(email: string): string {
  return validator.normalizeEmail(email, {
    all_lowercase: true,
    gmail_remove_dots: false,
    gmail_remove_subaddress: false,
  }) || email.toLowerCase().trim();
}

/**
 * Sanitize username
 */
export function sanitizeUsername(username: string): string {
  return username
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]/g, '');
}

/**
 * Escape HTML to prevent XSS
 */
export function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
    '/': '&#x2F;',
  };
  
  return text.replace(/[&<>"'/]/g, (char) => map[char]);
}

/**
 * Validate UUID format
 */
export function validateUUID(id: string): boolean {
  return validator.isUUID(id, 4);
}

/**
 * Normalize phone number to international format
 */
export function normalizePhoneNumber(phone: string, defaultCountry: string = 'US'): string | null {
  const cleaned = phone.replace(/\D/g, '');
  
  if (defaultCountry === 'US' && cleaned.length === 10) {
    return `+1${cleaned}`;
  }
  
  if (cleaned.startsWith('1') && cleaned.length === 11) {
    return `+${cleaned}`;
  }
  
  if (cleaned.startsWith('44') && cleaned.length >= 12) {
    return `+${cleaned}`;
  }
  
  return validator.isMobilePhone(phone, 'any') ? phone : null;
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  return validator.isEmail(email);
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string): boolean {
  return validator.isURL(url, {
    protocols: ['http', 'https'],
    require_protocol: true,
  });
}

/**
 * Sanitize and validate name
 */
export function sanitizeName(name: string): string {
  return name
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/[^a-zA-Z\s'-]/g, '')
    .slice(0, 100);
}

/**
 * Remove null bytes and control characters
 */
export function removeControlCharacters(text: string): string {
  return text.replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * Validate and sanitize alphanumeric string
 */
export function sanitizeAlphanumeric(text: string): string {
  return text.replace(/[^a-zA-Z0-9]/g, '');
}

/**
 * Validate credit card number (Luhn algorithm)
 */
export function isValidCreditCard(number: string): boolean {
  return validator.isCreditCard(number);
}

/**
 * Validate postal code
 */
export function isValidPostalCode(code: string, locale: string = 'US'): boolean {
  return validator.isPostalCode(code, locale as any);
}

/**
 * Sanitize file name
 */
export function sanitizeFileName(fileName: string): string {
  return fileName
    .replace(/[^a-zA-Z0-9.-]/g, '_')
    .replace(/_{2,}/g, '_')
    .toLowerCase();
}

/**
 * Validate date string
 */
export function isValidDate(date: string): boolean {
  return validator.isISO8601(date);
}

/**
 * Truncate string to max length
 */
export function truncate(text: string, maxLength: number, suffix: string = '...'): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - suffix.length) + suffix;
}

/**
 * Validate strong password
 */
export function isStrongPassword(password: string): boolean {
  return validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  });
}

/**
 * Sanitize SQL input (basic)
 */
export function sanitizeSQLInput(input: string): string {
  return input.replace(/['";\\]/g, '');
}

/**
 * Validate JSON string
 */
export function isValidJSON(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Remove extra whitespace
 */
export function normalizeWhitespace(text: string): string {
  return text.trim().replace(/\s+/g, ' ');
}