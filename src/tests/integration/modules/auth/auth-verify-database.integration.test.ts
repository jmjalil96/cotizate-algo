import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput, EmailVerificationInput } from '@/modules/auth/validators/auth.schema';
import jwt from 'jsonwebtoken';

describe('Auth Integration - Verify Database State', () => {
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

  describe('POST /api/v1/auth/verify - Database State Verification', () => {
    it('should update emailVerified flag', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Email',
        lastName: 'Verified',
        email: 'email.verified@example.com',
        organizationName: 'Email Verified Co',
        password: 'VerifiedPass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Step 2: Check initial state - emailVerified should be false
      const userBefore = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });

      expect(userBefore).toBeTruthy();
      expect(userBefore!.emailVerified).toBe(false);

      // Step 3: Get and use verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });

      const verifyData: EmailVerificationInput = {
        token: emailVerification!.token,
      };

      const response = await request(app).post('/api/v1/auth/verify').send(verifyData);

      expect(response.status).toBe(200);

      // Step 4: Check emailVerified flag is now true
      const userAfter = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });

      expect(userAfter).toBeTruthy();
      expect(userAfter!.emailVerified).toBe(true); // Should be updated to true

      // Verify the flag changed from false to true
      expect(userBefore!.emailVerified).toBe(false);
      expect(userAfter!.emailVerified).toBe(true);

      // Verify other fields remain consistent
      expect(userAfter!.id).toBe(userBefore!.id);
      expect(userAfter!.email).toBe(userBefore!.email);
    });

    it('should set emailVerifiedAt timestamp', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Timestamp',
        lastName: 'Test',
        email: 'timestamp.test@example.com',
        organizationName: 'Timestamp Testing Ltd',
        password: 'TimestampPass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Step 2: Check initial state - emailVerifiedAt should be null
      const userBefore = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });

      expect(userBefore).toBeTruthy();
      expect(userBefore!.emailVerifiedAt).toBeNull();

      // Record time before verification
      const timeBefore = Date.now();

      // Step 3: Get and use verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });

      const verifyData: EmailVerificationInput = {
        token: emailVerification!.token,
      };

      const response = await request(app).post('/api/v1/auth/verify').send(verifyData);

      expect(response.status).toBe(200);

      // Record time after verification
      const timeAfter = Date.now();

      // Step 4: Check emailVerifiedAt timestamp is set
      const userAfter = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });

      expect(userAfter).toBeTruthy();
      expect(userAfter!.emailVerifiedAt).not.toBeNull();
      expect(userAfter!.emailVerifiedAt).toBeInstanceOf(Date);

      // Verify timestamp is within expected range
      const verifiedAt = userAfter!.emailVerifiedAt!.getTime();
      expect(verifiedAt).toBeGreaterThanOrEqual(timeBefore);
      expect(verifiedAt).toBeLessThanOrEqual(timeAfter);

      // Verify the timestamp is recent (within last second)
      const now = Date.now();
      expect(now - verifiedAt).toBeLessThan(1000);

      // Verify the timestamp changed from null to a Date
      expect(userBefore!.emailVerifiedAt).toBeNull();
      expect(userAfter!.emailVerifiedAt).toBeInstanceOf(Date);
    });

    it('should create audit log for email verification', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Audit',
        lastName: 'Log',
        email: 'audit.log@example.com',
        organizationName: 'Audit Log Corp',
        password: 'AuditPass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Get user and organization
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
        include: {
          organizationUsers: {
            include: {
              organization: true,
            },
          },
        },
      });
      const organization = user!.organizationUsers[0].organization;

      // Step 2: Check initial audit logs (should have signup and org create)
      const auditLogsBefore = await prisma.auditLog.findMany({
        where: { userId: user!.id },
        orderBy: { createdAt: 'asc' },
      });

      expect(auditLogsBefore).toHaveLength(2); // user.signup and organization.create
      expect(auditLogsBefore[0].action).toBe('user.signup');
      expect(auditLogsBefore[1].action).toBe('organization.create');

      // Step 3: Get and use verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });

      const verifyData: EmailVerificationInput = {
        token: emailVerification!.token,
      };

      const response = await request(app)
        .post('/api/v1/auth/verify')
        .set('X-Forwarded-For', '192.168.1.50')
        .set('User-Agent', 'Test Browser')
        .send(verifyData);

      expect(response.status).toBe(200);

      // Step 4: Check audit log for email verification was created
      const auditLogsAfter = await prisma.auditLog.findMany({
        where: { userId: user!.id },
        orderBy: { createdAt: 'asc' },
      });

      expect(auditLogsAfter).toHaveLength(3); // Should have added one more

      // Check the new email verification audit log
      const verifyAuditLog = auditLogsAfter[2];
      expect(verifyAuditLog.action).toBe('user.email_verified');
      expect(verifyAuditLog.resource).toBe('user');
      expect(verifyAuditLog.resourceId).toBe(user!.id);
      expect(verifyAuditLog.userId).toBe(user!.id);
      expect(verifyAuditLog.organizationId).toBe(organization.id);
      expect(verifyAuditLog.ipAddress).toBe('192.168.1.50');
      expect(verifyAuditLog.details).toEqual(
        expect.objectContaining({
          email: signupData.email.toLowerCase(),
        }),
      );
      expect(verifyAuditLog.createdAt).toBeInstanceOf(Date);

      // Verify the audit log was created recently
      const now = Date.now();
      const auditTime = verifyAuditLog.createdAt.getTime();
      expect(now - auditTime).toBeLessThan(1000); // Within last second
    });

    it('should link session to correct user and organization', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Session',
        lastName: 'Link',
        email: 'session.link@example.com',
        organizationName: 'Session Link Inc',
        password: 'SessionPass123!',
      };

      await request(app).post('/api/v1/auth/signup').send(signupData);

      // Get user and organization
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
        include: {
          organizationUsers: {
            include: {
              organization: true,
            },
          },
        },
      });
      const organization = user!.organizationUsers[0].organization;

      // Step 2: Get and use verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() },
      });

      const verifyData: EmailVerificationInput = {
        token: emailVerification!.token,
      };

      const response = await request(app)
        .post('/api/v1/auth/verify')
        .set('X-Forwarded-For', '10.0.0.100')
        .set('User-Agent', 'Mozilla/5.0 Test')
        .send(verifyData);

      expect(response.status).toBe(200);

      // Extract tokens from response
      const { accessToken, refreshToken } = response.body.data;
      expect(accessToken).toBeTruthy();
      expect(refreshToken).toBeTruthy();

      // Step 3: Verify session was created and linked correctly
      const sessions = await prisma.session.findMany({
        where: { userId: user!.id },
      });

      expect(sessions).toHaveLength(1);
      const session = sessions[0];

      // Verify session is linked to correct user
      expect(session.userId).toBe(user!.id);
      expect(session.ipAddress).toBe('10.0.0.100');
      expect(session.userAgent).toContain('Mozilla/5.0 Test');

      // Step 4: Decode JWT to verify organization link
      const decoded = jwt.decode(accessToken) as any;
      expect(decoded).toBeTruthy();
      expect(decoded.userId).toBe(user!.id);
      expect(decoded.organizationId).toBe(organization.id);
      expect(decoded.sessionId).toBe(session.id);
      expect(decoded.email).toBe(signupData.email.toLowerCase());

      // Step 5: Verify refresh token is linked to session and user
      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId: user!.id },
      });

      expect(refreshTokens).toHaveLength(1);
      const refreshTokenRecord = refreshTokens[0];

      expect(refreshTokenRecord.userId).toBe(user!.id);
      expect(refreshTokenRecord.token).toBe(refreshToken);

      // Step 6: Verify organization relationship
      const orgUser = await prisma.organizationUser.findFirst({
        where: {
          userId: user!.id,
          organizationId: organization.id,
        },
        include: {
          role: true,
        },
      });

      expect(orgUser).toBeTruthy();
      expect(orgUser!.role.name).toBe('owner');

      // Verify all components are linked correctly
      expect(session.userId).toBe(user!.id);
      expect(refreshTokenRecord.userId).toBe(user!.id);
      expect(decoded.userId).toBe(user!.id);
      expect(decoded.organizationId).toBe(organization.id);
      expect(orgUser!.userId).toBe(user!.id);
      expect(orgUser!.organizationId).toBe(organization.id);
    });
  });
});
