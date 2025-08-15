import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput, EmailVerificationInput } from '@/modules/auth/validators/auth.schema';
import jwt from 'jsonwebtoken';
import { env } from '@/core/config/env';

describe('E2E - Complete Auth Flow', () => {
  let app: Application;

  beforeAll(async () => {
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
        organizationId: null,
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
    await prisma.$disconnect();
  });

  beforeEach(async () => {
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

  describe('Complete Signup-Verify Flow', () => {
    it('should complete full user journey from signup to verified session', async () => {
      // Step 1: Signup with valid data
      const signupData: SignupInput = {
        firstName: 'E2E',
        lastName: 'User',
        email: 'e2e.user@example.com',
        organizationName: 'E2E Test Organization',
        password: 'E2ESecurePass123!',
      };

      const signupResponse = await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData)
        .set('X-Forwarded-For', '192.168.1.100')
        .set('User-Agent', 'E2E Test Browser');

      // Verify signup response
      expect(signupResponse.status).toBe(201);
      expect(signupResponse.body.success).toBe(true);
      expect(signupResponse.body.data.message).toContain('Account created successfully');
      expect(signupResponse.body.data.user.email).toBe(signupData.email.toLowerCase());
      expect(signupResponse.body.data.organization.name).toBe(signupData.organizationName);
      expect(signupResponse.body.data.organization.slug).toBeTruthy();

      // Step 2: Verify database state after signup
      const userAfterSignup = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
        include: {
          profile: true,
          organizationUsers: {
            include: {
              organization: true,
              role: true,
            },
          },
        },
      });

      expect(userAfterSignup).toBeTruthy();
      expect(userAfterSignup!.status).toBe('PENDING');
      expect(userAfterSignup!.emailVerified).toBe(false);
      expect(userAfterSignup!.emailVerifiedAt).toBeNull();
      expect(userAfterSignup!.profile).toBeTruthy();
      expect(userAfterSignup!.profile!.firstName).toBe(signupData.firstName);
      expect(userAfterSignup!.profile!.lastName).toBe(signupData.lastName);
      expect(userAfterSignup!.organizationUsers).toHaveLength(1);
      expect(userAfterSignup!.organizationUsers[0].role.name).toBe('owner');

      // Step 3: Get verification token from database
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { userId: userAfterSignup!.id },
      });

      expect(emailVerification).toBeTruthy();
      expect(emailVerification!.email).toBe(signupData.email.toLowerCase());
      expect(emailVerification!.expiresAt.getTime()).toBeGreaterThan(Date.now());

      // Step 4: Check audit logs after signup
      const auditLogsAfterSignup = await prisma.auditLog.findMany({
        where: { userId: userAfterSignup!.id },
        orderBy: { createdAt: 'asc' },
      });

      expect(auditLogsAfterSignup).toHaveLength(2);
      expect(auditLogsAfterSignup[0].action).toBe('user.signup');
      expect(auditLogsAfterSignup[1].action).toBe('organization.create');

      // Step 5: Verify email with token
      const verifyData: EmailVerificationInput = {
        token: emailVerification!.token,
      };

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send(verifyData)
        .set('X-Forwarded-For', '192.168.1.100')
        .set('User-Agent', 'E2E Test Browser');

      // Verify response
      expect(verifyResponse.status).toBe(200);
      expect(verifyResponse.body.success).toBe(true);
      expect(verifyResponse.body.data.accessToken).toBeTruthy();
      expect(verifyResponse.body.data.refreshToken).toBeTruthy();
      expect(verifyResponse.body.data.user.id).toBe(userAfterSignup!.id);
      expect(verifyResponse.body.data.user.email).toBe(signupData.email.toLowerCase());
      expect(verifyResponse.body.data.organization.id).toBe(
        userAfterSignup!.organizationUsers[0].organizationId,
      );

      // Step 6: Validate JWT token
      const { accessToken, refreshToken } = verifyResponse.body.data;
      const decoded = jwt.verify(accessToken, env.JWT_SECRET as string) as any;

      expect(decoded.userId).toBe(userAfterSignup!.id);
      expect(decoded.email).toBe(signupData.email.toLowerCase());
      expect(decoded.organizationId).toBe(userAfterSignup!.organizationUsers[0].organizationId);
      expect(decoded.sessionId).toBeTruthy();
      expect(decoded.jti).toBeTruthy();
      expect(decoded.exp - decoded.iat).toBe(60 * 60); // 1 hour

      // Step 7: Verify database state after verification
      const userAfterVerify = await prisma.user.findUnique({
        where: { id: userAfterSignup!.id },
      });

      expect(userAfterVerify!.status).toBe('ACTIVE');
      expect(userAfterVerify!.emailVerified).toBe(true);
      expect(userAfterVerify!.emailVerifiedAt).toBeInstanceOf(Date);

      // Step 8: Verify session created
      const session = await prisma.session.findFirst({
        where: { userId: userAfterSignup!.id },
      });

      expect(session).toBeTruthy();
      expect(session!.id).toBe(decoded.sessionId);
      expect(session!.isActive).toBe(true);
      expect(session!.ipAddress).toBe('192.168.1.100');
      expect(session!.userAgent).toContain('E2E Test Browser');

      // Step 9: Verify refresh token created
      const refreshTokenRecord = await prisma.refreshToken.findFirst({
        where: { userId: userAfterSignup!.id },
      });

      expect(refreshTokenRecord).toBeTruthy();
      expect(refreshTokenRecord!.token).toBe(refreshToken);
      expect(refreshTokenRecord!.isRevoked).toBe(false);

      // Step 10: Verify verification token deleted
      const deletedVerificationToken = await prisma.emailVerification.findFirst({
        where: { userId: userAfterSignup!.id },
      });

      expect(deletedVerificationToken).toBeNull();

      // Step 11: Verify audit logs after verification
      const auditLogsAfterVerify = await prisma.auditLog.findMany({
        where: { userId: userAfterSignup!.id },
        orderBy: { createdAt: 'asc' },
      });

      expect(auditLogsAfterVerify).toHaveLength(3);
      expect(auditLogsAfterVerify[2].action).toBe('user.email_verified');
      expect(auditLogsAfterVerify[2].ipAddress).toBe('192.168.1.100');

      // Step 12: Verify password history created
      const passwordHistory = await prisma.passwordHistory.findMany({
        where: { userId: userAfterSignup!.id },
      });

      expect(passwordHistory).toHaveLength(1);
      expect(passwordHistory[0].passwordHash).toBeTruthy();
    });

    it('should prevent multiple users with same organization name', async () => {
      // Create first user with organization
      const firstUser: SignupInput = {
        firstName: 'First',
        lastName: 'Owner',
        email: 'first.owner@example.com',
        organizationName: 'Unique Organization',
        password: 'FirstPass123!',
      };

      const firstResponse = await request(app).post('/api/v1/auth/signup').send(firstUser);

      expect(firstResponse.status).toBe(201);

      // Attempt to create second user with same organization
      const secondUser: SignupInput = {
        firstName: 'Second',
        lastName: 'User',
        email: 'second.user@example.com',
        organizationName: 'Unique Organization', // Same org name
        password: 'SecondPass123!',
      };

      const secondResponse = await request(app).post('/api/v1/auth/signup').send(secondUser);

      expect(secondResponse.status).toBe(409);
      expect(secondResponse.body.error.message).toContain('Organization name already taken');

      // Verify only one organization exists
      const organizations = await prisma.organization.findMany({
        where: { name: 'Unique Organization' },
      });

      expect(organizations).toHaveLength(1);
    });

    it('should handle case sensitivity correctly throughout flow', async () => {
      // Signup with mixed case email
      const signupData: SignupInput = {
        firstName: 'Case',
        lastName: 'Test',
        email: 'CaSe.TeSt@ExAmPlE.CoM', // Mixed case
        organizationName: 'Case Test Org',
        password: 'CasePass123!',
      };

      const signupResponse = await request(app).post('/api/v1/auth/signup').send(signupData);

      expect(signupResponse.status).toBe(201);
      expect(signupResponse.body.data.user.email).toBe('case.test@example.com'); // Lowercased

      // Verify user stored with lowercase email
      const user = await prisma.user.findUnique({
        where: { email: 'case.test@example.com' },
      });

      expect(user).toBeTruthy();

      // Get verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: 'case.test@example.com' }, // Must use lowercase
      });

      expect(emailVerification).toBeTruthy();

      // Verify with token
      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send({ token: emailVerification!.token });

      expect(verifyResponse.status).toBe(200);

      // Decode JWT to verify email is lowercase
      const { accessToken } = verifyResponse.body.data;
      const decoded = jwt.decode(accessToken) as any;
      expect(decoded.email).toBe('case.test@example.com');
    });
  });
});
