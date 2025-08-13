/**
 * Example of how to use validation in routes
 * Rename to auth.routes.ts and implement controllers to use
 */

import { Router } from 'express';
import { validate } from '../../common/validators';
import {
  loginSchema,
  registerSchema,
  refreshTokenSchema,
  changePasswordSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
} from '../../common/validators/schemas';

const router = Router();

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *               name:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         $ref: '#/components/schemas/Error'
 */
// router.post('/register', validate(registerSchema), registerController);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
// router.post('/login', validate(loginSchema), loginController);

// router.post('/refresh', validate(refreshTokenSchema), refreshTokenController);
// router.post('/logout', logoutController);
// router.post('/password/reset-request', validate(passwordResetRequestSchema), passwordResetRequestController);
// router.post('/password/reset', validate(passwordResetSchema), passwordResetController);
// router.post('/password/change', authenticate, validate(changePasswordSchema), changePasswordController);

export default router;
