import { Router } from 'express';
import { Request, Response } from 'express';
import {
  authenticate,
  authenticateWithSession,
  authenticateOptional,
} from '../middlewares/auth.middleware';

const router = Router();

/**
 * PUBLIC ENDPOINTS - No authentication required
 */
router.get('/public/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Service is healthy',
    authentication: 'none',
  });
});

/**
 * OPTIONAL AUTH - Works with or without token
 */
router.get('/products', authenticateOptional(), (req: Request, res: Response) => {
  if (req.user) {
    res.json({
      success: true,
      message: 'Viewing products with user preferences',
      userId: req.user.userId,
      authentication: 'optional (user authenticated)',
    });
  } else {
    res.json({
      success: true,
      message: 'Viewing products as guest',
      authentication: 'optional (guest)',
    });
  }
});

/**
 * MODE A: JWT-ONLY (Fast) - For non-critical operations
 * These endpoints only verify JWT signature and expiry
 * JWT still works for ~15 minutes after logout
 */

// Reading data
router.get('/profile', authenticate(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Profile data',
    userId: req.user?.userId,
    sessionId: req.user?.sessionId,
    authentication: 'jwt-only (fast)',
  });
});

// Viewing lists
router.get('/customers', authenticate(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Customer list',
    authentication: 'jwt-only (fast)',
  });
});

// Non-sensitive updates
router.put('/preferences', authenticate(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Preferences updated',
    authentication: 'jwt-only (fast)',
  });
});

/**
 * MODE B: JWT + SESSION (Secure) - For critical operations
 * These endpoints verify JWT AND check session is still active
 * Access revoked immediately when session is terminated
 */

// Financial operations
router.post('/payment', authenticateWithSession(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Payment processed',
    userId: req.user?.userId,
    sessionId: req.user?.sessionId,
    authentication: 'jwt+session (secure)',
  });
});

// Deleting resources
router.delete('/account', authenticateWithSession(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Account deletion initiated',
    authentication: 'jwt+session (secure)',
  });
});

// Admin operations
router.post(
  '/admin/users/:id/suspend',
  authenticateWithSession(),
  (req: Request, res: Response) => {
    res.json({
      success: true,
      message: `User ${req.params.id} suspended`,
      authentication: 'jwt+session (secure)',
    });
  },
);

// Changing security settings
router.put('/security/password', authenticateWithSession(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Password changed',
    authentication: 'jwt+session (secure)',
  });
});

// Sensitive data access
router.get('/billing/credit-cards', authenticateWithSession(), (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'Credit card information',
    authentication: 'jwt+session (secure)',
  });
});

/**
 * DEMONSTRATION: What happens when admin revokes a session
 *
 * Timeline:
 * 10:00 AM - User logs in, gets JWT (expires 10:15 AM) and session
 * 10:05 AM - User makes request to /profile (JWT-only) - WORKS
 * 10:05 AM - User makes request to /payment (JWT+Session) - WORKS
 * 10:06 AM - Admin revokes user's session
 * 10:07 AM - User makes request to /profile (JWT-only) - STILL WORKS (JWT valid until 10:15)
 * 10:07 AM - User makes request to /payment (JWT+Session) - BLOCKED (session inactive)
 * 10:15 AM - JWT expires
 * 10:16 AM - User tries to refresh - BLOCKED (refresh token linked to inactive session)
 * 10:16 AM - User makes request to /profile - BLOCKED (JWT expired)
 */

export default router;
