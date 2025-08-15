import {
  add,
  addBusinessDays,
  formatDistance,
  formatDistanceToNow,
  isAfter,
  isBefore,
  parseISO,
} from 'date-fns';

/**
 * Parse duration string to Date
 * Examples: "15m", "1h", "7d", "30d"
 */
export function getExpiryDate(duration: string): Date {
  const now = new Date();
  const match = duration.match(/^(\d+)([mhd])$/);

  if (!match) {
    throw new Error(`Invalid duration format: ${duration}`);
  }

  const [, value, unit] = match;
  const amount = parseInt(value, 10);

  switch (unit) {
    case 'm':
      return add(now, { minutes: amount });
    case 'h':
      return add(now, { hours: amount });
    case 'd':
      return add(now, { days: amount });
    default:
      throw new Error(`Invalid duration unit: ${unit}`);
  }
}

/**
 * Check if a date has expired
 */
export function isExpired(date: Date | string): boolean {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return isBefore(dateObj, new Date());
}

/**
 * Check if a date is in the future
 */
export function isFuture(date: Date | string): boolean {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return isAfter(dateObj, new Date());
}

/**
 * Get human-readable time until expiry
 */
export function timeUntilExpiry(date: Date | string): string {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;

  if (isExpired(dateObj)) {
    return 'Expired';
  }

  return formatDistanceToNow(dateObj, { addSuffix: true });
}

/**
 * Get human-readable time between two dates
 */
export function timeBetween(date1: Date | string, date2: Date | string): string {
  const dateObj1 = typeof date1 === 'string' ? parseISO(date1) : date1;
  const dateObj2 = typeof date2 === 'string' ? parseISO(date2) : date2;

  return formatDistance(dateObj1, dateObj2);
}

/**
 * Add business days (skip weekends)
 */
export function addBusinessDaysToDate(date: Date, days: number): Date {
  return addBusinessDays(date, days);
}

/**
 * Get Unix timestamp in seconds
 */
export function getUnixTimestamp(date: Date = new Date()): number {
  return Math.floor(date.getTime() / 1000);
}

/**
 * Convert Unix timestamp to Date
 */
export function fromUnixTimestamp(timestamp: number): Date {
  return new Date(timestamp * 1000);
}

/**
 * Get start of day
 */
export function getStartOfDay(date: Date = new Date()): Date {
  const result = new Date(date);
  result.setHours(0, 0, 0, 0);
  return result;
}

/**
 * Get end of day
 */
export function getEndOfDay(date: Date = new Date()): Date {
  const result = new Date(date);
  result.setHours(23, 59, 59, 999);
  return result;
}

/**
 * Calculate age in years
 */
export function calculateAge(birthDate: Date | string): number {
  const birth = typeof birthDate === 'string' ? parseISO(birthDate) : birthDate;
  const today = new Date();
  let age = today.getFullYear() - birth.getFullYear();
  const monthDiff = today.getMonth() - birth.getMonth();

  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
    age--;
  }

  return age;
}

/**
 * Check if date is within range
 */
export function isWithinRange(
  date: Date | string,
  startDate: Date | string,
  endDate: Date | string,
): boolean {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  const start = typeof startDate === 'string' ? parseISO(startDate) : startDate;
  const end = typeof endDate === 'string' ? parseISO(endDate) : endDate;

  return isAfter(dateObj, start) && isBefore(dateObj, end);
}

/**
 * Get milliseconds until a specific date
 */
export function millisecondsUntil(date: Date | string): number {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return Math.max(0, dateObj.getTime() - Date.now());
}

/**
 * Convert milliseconds to duration object
 */
export function millisecondsToDuration(ms: number): {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
} {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  return {
    days,
    hours: hours % 24,
    minutes: minutes % 60,
    seconds: seconds % 60,
  };
}
