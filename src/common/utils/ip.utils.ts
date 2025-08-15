import { Request } from 'express';

/**
 * Extract the client's IP address from the request
 * Handles various proxy and load balancer scenarios
 */
export function getClientIp(req: Request): string {
  // Check for common proxy headers
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    // X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
    // We want the first one (the original client)
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor.split(',')[0];
    return ips.trim();
  }

  // Check for other common headers used by proxies
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return Array.isArray(realIp) ? realIp[0] : realIp;
  }

  // Cloudflare specific header
  const cfConnectingIp = req.headers['cf-connecting-ip'];
  if (cfConnectingIp) {
    return Array.isArray(cfConnectingIp) ? cfConnectingIp[0] : cfConnectingIp;
  }

  // Fallback to req.ip (Express's built-in IP detection)
  // This works when trust proxy is configured
  if (req.ip) {
    return req.ip;
  }

  // Last resort: use the socket connection remote address
  // Remove IPv6 prefix if present (::ffff:)
  const socketIp = req.socket?.remoteAddress || '';
  return socketIp.replace(/^::ffff:/, '');
}

/**
 * Check if an IP address is a private/internal IP
 */
export function isPrivateIp(ip: string): boolean {
  // Remove IPv6 prefix if present
  const cleanIp = ip.replace(/^::ffff:/, '');

  // Check for localhost
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') {
    return true;
  }

  // Check for private IPv4 ranges
  const parts = cleanIp.split('.').map(Number);
  if (parts.length === 4) {
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
  }

  return false;
}

/**
 * Anonymize an IP address for privacy
 * For IPv4: Replace last octet with 0
 * For IPv6: Replace last 4 groups with 0
 */
export function anonymizeIp(ip: string): string {
  // Remove IPv6 prefix if present
  const cleanIp = ip.replace(/^::ffff:/, '');

  // Check if IPv4
  if (cleanIp.includes('.')) {
    const parts = cleanIp.split('.');
    if (parts.length === 4) {
      parts[3] = '0';
      return parts.join('.');
    }
  }

  // Check if IPv6
  if (cleanIp.includes(':')) {
    const parts = cleanIp.split(':');
    // Replace last 4 groups with 0
    for (let i = Math.max(0, parts.length - 4); i < parts.length; i++) {
      parts[i] = '0';
    }
    return parts.join(':');
  }

  return cleanIp;
}
