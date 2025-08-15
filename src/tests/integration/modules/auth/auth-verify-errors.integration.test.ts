import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput, EmailVerificationInput } from '@/modules/auth/validators/auth.schema';

describe('Auth Integration - Verify Error Scenarios', () => {
  let app: Application;

  beforeAll(async () => {
    // Create Express app instance
    app = createApp();

    // Clean database before tests
    await prisma.$transaction([
      prisma.auditLog.deleteMany(),
      prisma.passwordHistory.deleteMany(),
      prisma.emailVerification.deleteMany(),
      prisma.refreshToken.deleteMany(),
      prisma.session.deleteMany(),
      prisma.organizationUser.deleteMany(),
      prisma.profile.deleteMany(),
      prisma.user.deleteMany(),
      prisma.organization.deleteMany(),
    ]);

    // Ensure owner role exists
    const ownerRole = await prisma.role.findFirst({
      where: {
        name: 'owner',
        organizationId: null, // System role
      },
    });

    if (!ownerRole) {
      await prisma.role.create({
        data: {
          name: 'owner',
          description: 'Organization owner with full permissions',
        },
      });
    }
  });

  afterAll(async () => {
    // Clean up and close database connection
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    // Clean user-related data before each test
    await prisma.$transaction([
      prisma.auditLog.deleteMany(),
      prisma.passwordHistory.deleteMany(),
      prisma.emailVerification.deleteMany(),
      prisma.refreshToken.deleteMany(),
      prisma.session.deleteMany(),
      prisma.organizationUser.deleteMany(),
      prisma.profile.deleteMany(),
      prisma.user.deleteMany(),
      prisma.organization.deleteMany(),
    ]);
  });

  describe('POST /api/v1/auth/verify - Error Handling', () => {
    it('should return 404 for invalid token', async () => {
      // Try to verify with a non-existent token
      const verifyData: EmailVerificationInput = {
        token: 'invalid-token-that-does-not-exist-123456789',
      };

      const response = await request(app).post('/api/v1/auth/verify').send(verifyData);

      expect(response.status).toBe(404);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('invalid');
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Verify no session was created
      const sessions = await prisma.session.findMany();
      expect(sessions).toHaveLength(0);

      // Verify no refresh token was created
      const refreshTokens = await prisma.refreshToken.findMany();
      expect(refreshTokens).toHaveLength(0);

      // Try with different formats of invalid tokens
      const invalidTokenFormats = [
        'short',
        '123',
        'abc-def-ghi',
        '00000000-0000-0000-0000-000000000000',
        'this-is-definitely-not-a-valid-token',
      ];

      for (const invalidToken of invalidTokenFormats) {
        const response = await request(app)
          .post('/api/v1/auth/verify')
          .send({ token: invalidToken });

        expect(response.status).toBe(404);
        expect(response.body.error.message.toLowerCase()).toContain('invalid');
      }
    });

    it('should return 401 for expired token', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Expired',
        lastName: 'Token',
        email: 'expired.token@example.com',
        organizationName: 'Expired Token Corp',
        password: 'ExpiredPass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Step 2: Get the verification token and manually expire it
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });

      expect(emailVerification).toBeTruthy();
      const expiredToken = emailVerification!.token;

      // Update the token to be expired (set expiry to 1 hour ago)
      await prisma.emailVerification.update({
        where: { id: emailVerification!.id },
        data: {
          expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
        },
      });

      // Step 3: Try to verify with expired token
      const verifyData: EmailVerificationInput = {
        token: expiredToken,
      };

      const response = await request(app).post('/api/v1/auth/verify').send(verifyData);

      // Step 4: Assert 401 response
      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('expired');

      // Step 5: Verify no session or tokens were created
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });

      const sessions = await prisma.session.findMany({
        where: { userId: user!.id },
      });
      expect(sessions).toHaveLength(0);

      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId: user!.id },
      });
      expect(refreshTokens).toHaveLength(0);

      // Verify user status remains PENDING
      expect(user!.status).toBe('PENDING');
      expect(user!.emailVerified).toBe(false);

      // Verify the expired token still exists (not deleted on failure)
      const tokenStillExists = await prisma.emailVerification.findUnique({
        where: { id: emailVerification!.id },
      });
      expect(tokenStillExists).toBeTruthy();
    });

    it('should return 400 for missing token', async () => {
      // Test with no token field at all
      let response = await request(app).post('/api/v1/auth/verify').send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Test with null token
      response = await request(app).post('/api/v1/auth/verify').send({ token: null });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with undefined token (will be stripped by JSON)
      response = await request(app).post('/api/v1/auth/verify').send({ token: undefined });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with empty string token
      response = await request(app).post('/api/v1/auth/verify').send({ token: '' });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Test with whitespace-only token (may be trimmed and treated as invalid)
      response = await request(app).post('/api/v1/auth/verify').send({ token: '   ' });

      // Whitespace might be trimmed and treated as invalid token (404) or validation error (400)
      expect([400, 404]).toContain(response.status);
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Test with wrong field name
      response = await request(app)
        .post('/api/v1/auth/verify')
        .send({ verification_token: 'valid-looking-token' });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Test with extra fields but missing token
      response = await request(app).post('/api/v1/auth/verify').send({
        email: 'test@example.com',
        userId: '123',
        randomField: 'value',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('token');

      // Verify no sessions or tokens were created
      const sessions = await prisma.session.findMany();
      expect(sessions).toHaveLength(0);

      const refreshTokens = await prisma.refreshToken.findMany();
      expect(refreshTokens).toHaveLength(0);
    });

    it('should prevent double verification', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Double',
        lastName: 'Verify',
        email: 'double.verify@example.com',
        organizationName: 'Double Verify Inc',
        password: 'DoublePass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Step 2: Get the verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });
      const verificationToken = emailVerification!.token;

      // Step 3: First verification - should succeed
      const firstVerifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      const firstResponse = await request(app).post('/api/v1/auth/verify').send(firstVerifyData);

      expect(firstResponse.status).toBe(200);
      expect(firstResponse.body).toHaveProperty('success', true);
      expect(firstResponse.body.data).toHaveProperty('accessToken');
      expect(firstResponse.body.data).toHaveProperty('refreshToken');

      // Verify user is now active
      const userAfterFirst = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });
      expect(userAfterFirst!.status).toBe('ACTIVE');
      expect(userAfterFirst!.emailVerified).toBe(true);

      // Step 4: Second verification attempt - should fail (token deleted)
      const secondResponse = await request(app).post('/api/v1/auth/verify').send(firstVerifyData);

      expect(secondResponse.status).toBe(404); // Token no longer exists
      expect(secondResponse.body).toHaveProperty('error');
      expect(secondResponse.body.error.message.toLowerCase()).toContain('invalid');

      // Step 5: Verify only one session was created (from first verification)
      const sessions = await prisma.session.findMany({
        where: { userId: userAfterFirst!.id },
      });
      expect(sessions).toHaveLength(1); // Only one from successful verification

      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId: userAfterFirst!.id },
      });
      expect(refreshTokens).toHaveLength(1); // Only one from successful verification

      // Verify user status remains ACTIVE (not affected by second attempt)
      const userAfterSecond = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });
      expect(userAfterSecond!.status).toBe('ACTIVE');
      expect(userAfterSecond!.emailVerified).toBe(true);

      // Verify no new audit logs were created for the failed attempt
      const auditLogs = await prisma.auditLog.findMany({
        where: {
          userId: userAfterFirst!.id,
          action: 'user.email_verified',
        },
      });
      expect(auditLogs).toHaveLength(1); // Only one from successful verification
    });
  });
});
