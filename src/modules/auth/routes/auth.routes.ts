import { Router } from 'express';
import { validate } from '@/common/middlewares/validation.middleware';
import { authController } from '../controllers/auth.controller';
import { signupSchema, emailVerificationSchema } from '../validators/auth.schema';

const router = Router();

/**
 * @swagger
 * /api/v1/auth/signup:
 *   post:
 *     summary: Create a new account with organization
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - organizationName
 *               - email
 *               - password
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               organizationName:
 *                 type: string
 *                 example: Acme Corp
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: SecureP@ssw0rd!
 *     responses:
 *       201:
 *         description: Account created successfully
 *       400:
 *         description: Validation error
 *       409:
 *         description: Email or organization already exists
 */
router.post('/signup', validate(signupSchema), authController.signup);

/**
 * @swagger
 * /api/v1/auth/verify:
 *   post:
 *     summary: Verify email address and activate account
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *                 example: abc123def456...
 *     responses:
 *       200:
 *         description: Email verified successfully, returns JWT tokens
 *       404:
 *         description: Invalid or expired token
 */
router.post('/verify', validate(emailVerificationSchema), authController.verify);

export default router;