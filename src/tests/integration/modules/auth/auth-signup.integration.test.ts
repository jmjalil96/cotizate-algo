import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

describe('Auth Integration - Signup Endpoint', () => {
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

  describe('POST /api/v1/auth/signup', () => {
    it('should successfully create a new user account', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        organizationName: 'Test Organization',
        password: 'SecurePass123!',
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData)
        .expect('Content-Type', /json/);

      // Assert
      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      
      const { data } = response.body;
      expect(data).toHaveProperty('message');
      expect(data.message).toContain('Account created successfully');
      expect(data).toHaveProperty('user');
      expect(data.user).toHaveProperty('id');
      expect(data.user).toHaveProperty('email', signupData.email.toLowerCase());
      expect(data).toHaveProperty('organization');
      expect(data.organization).toHaveProperty('id');
      expect(data.organization).toHaveProperty('name', signupData.organizationName);
      expect(data.organization).toHaveProperty('slug');

      // Verify user was created in database
      const createdUser = await prisma.user.findUnique({
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

      expect(createdUser).toBeTruthy();
      expect(createdUser?.status).toBe('PENDING');
      expect(createdUser?.emailVerified).toBe(false);
      expect(createdUser?.profile?.firstName).toBe(signupData.firstName);
      expect(createdUser?.profile?.lastName).toBe(signupData.lastName);
      expect(createdUser?.organizationUsers).toHaveLength(1);
      expect(createdUser?.organizationUsers[0].role.name).toBe('owner');
      expect(createdUser?.organizationUsers[0].organization.name).toBe(signupData.organizationName);

      // Verify email verification token was created
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { userId: createdUser?.id },
      });
      expect(emailVerification).toBeTruthy();
      expect(emailVerification?.email).toBe(signupData.email.toLowerCase());
      expect(emailVerification?.token).toBeTruthy();
      expect(emailVerification?.expiresAt).toBeInstanceOf(Date);

      // Verify password history was created
      const passwordHistory = await prisma.passwordHistory.findFirst({
        where: { userId: createdUser?.id },
      });
      expect(passwordHistory).toBeTruthy();
      expect(passwordHistory?.passwordHash).toBeTruthy();

      // Verify audit logs were created
      const auditLogs = await prisma.auditLog.findMany({
        where: { userId: createdUser?.id },
        orderBy: { createdAt: 'asc' },
      });
      expect(auditLogs).toHaveLength(2);
      expect(auditLogs[0].action).toBe('user.signup');
      expect(auditLogs[1].action).toBe('organization.create');
    });

    it('should create all required database records', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        organizationName: 'Smith Corp',
        password: 'AnotherPass456!',
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Assert
      expect(response.status).toBe(201);

      // Get the created user
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });
      expect(user).toBeTruthy();
      const userId = user!.id;

      // 1. Verify User record
      expect(user?.email).toBe(signupData.email.toLowerCase());
      expect(user?.status).toBe('PENDING');
      expect(user?.emailVerified).toBe(false);
      expect(user?.passwordHash).toBeTruthy();
      expect(user?.passwordHash).not.toBe(signupData.password); // Should be hashed

      // 2. Verify Profile record
      const profile = await prisma.profile.findUnique({
        where: { userId },
      });
      expect(profile).toBeTruthy();
      expect(profile?.firstName).toBe(signupData.firstName);
      expect(profile?.lastName).toBe(signupData.lastName);

      // 3. Verify Organization record
      const organization = await prisma.organization.findFirst({
        where: { name: signupData.organizationName },
      });
      expect(organization).toBeTruthy();
      expect(organization?.name).toBe(signupData.organizationName);
      expect(organization?.slug).toBeTruthy();

      // 4. Verify OrganizationUser record
      const orgUser = await prisma.organizationUser.findFirst({
        where: {
          userId,
          organizationId: organization!.id,
        },
        include: { role: true },
      });
      expect(orgUser).toBeTruthy();
      expect(orgUser?.role.name).toBe('owner');

      // 5. Verify EmailVerification record
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { userId },
      });
      expect(emailVerification).toBeTruthy();
      expect(emailVerification?.email).toBe(signupData.email.toLowerCase());
      expect(emailVerification?.token).toBeTruthy();
      expect(emailVerification?.expiresAt).toBeInstanceOf(Date);
      // Check expiry is in the future (approximately 24 hours)
      const expiryTime = emailVerification!.expiresAt.getTime();
      const expectedExpiry = Date.now() + 24 * 60 * 60 * 1000;
      expect(expiryTime).toBeGreaterThan(Date.now());
      expect(Math.abs(expiryTime - expectedExpiry)).toBeLessThan(60000); // Within 1 minute

      // 6. Verify PasswordHistory record
      const passwordHistory = await prisma.passwordHistory.findMany({
        where: { userId },
      });
      expect(passwordHistory).toHaveLength(1);
      expect(passwordHistory[0].passwordHash).toBe(user?.passwordHash);
      expect(passwordHistory[0].createdAt).toBeInstanceOf(Date);

      // 7. Verify AuditLog records
      const auditLogs = await prisma.auditLog.findMany({
        where: { userId },
        orderBy: { createdAt: 'asc' },
      });
      expect(auditLogs).toHaveLength(2);
      
      // First audit log - user signup
      expect(auditLogs[0].action).toBe('user.signup');
      expect(auditLogs[0].resource).toBe('user');
      expect(auditLogs[0].resourceId).toBe(userId);
      expect(auditLogs[0].details).toEqual(expect.objectContaining({
        email: signupData.email.toLowerCase(),
        firstName: signupData.firstName,
        lastName: signupData.lastName,
      }));
      
      // Second audit log - organization create
      expect(auditLogs[1].action).toBe('organization.create');
      expect(auditLogs[1].resource).toBe('organization');
      expect(auditLogs[1].resourceId).toBe(organization!.id);
      expect(auditLogs[1].organizationId).toBe(organization!.id);
      expect(auditLogs[1].details).toEqual(expect.objectContaining({
        name: signupData.organizationName,
        slug: organization!.slug,
      }));
    });

    it('should not create session before verification', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob.johnson@example.com',
        organizationName: 'Johnson Industries',
        password: 'BobPass789!',
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Assert
      expect(response.status).toBe(201);

      // Get the created user
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
      });
      expect(user).toBeTruthy();
      const userId = user!.id;

      // Verify NO session was created
      const sessions = await prisma.session.findMany({
        where: { userId },
      });
      expect(sessions).toHaveLength(0);

      // Verify NO refresh token was created
      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId },
      });
      expect(refreshTokens).toHaveLength(0);

      // Verify user status is PENDING (not ACTIVE)
      expect(user?.status).toBe('PENDING');
      expect(user?.emailVerified).toBe(false);
      expect(user?.emailVerifiedAt).toBeNull();

      // Verify email verification token WAS created (needed for verification)
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { userId },
      });
      expect(emailVerification).toBeTruthy();
      expect(emailVerification?.token).toBeTruthy();

      // Verify response does NOT include tokens
      expect(response.body.data).not.toHaveProperty('accessToken');
      expect(response.body.data).not.toHaveProperty('refreshToken');
      expect(response.body.data).not.toHaveProperty('tokens');
      
      // Verify response includes message about email verification
      expect(response.body.data.message).toContain('check your email');
    });

    it('should validate required fields', async () => {
      // Test missing firstName
      let response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          lastName: 'Doe',
          email: 'test@example.com',
          organizationName: 'Test Org',
          password: 'Pass123!',
        });
      expect(response.status).toBe(400);
      expect(response.body.error).toBeTruthy();

      // Test missing lastName
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          email: 'test@example.com',
          organizationName: 'Test Org',
          password: 'Pass123!',
        });
      expect(response.status).toBe(400);

      // Test missing email
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          organizationName: 'Test Org',
          password: 'Pass123!',
        });
      expect(response.status).toBe(400);

      // Test missing organizationName
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test@example.com',
          password: 'Pass123!',
        });
      expect(response.status).toBe(400);

      // Test missing password
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test@example.com',
          organizationName: 'Test Org',
        });
      expect(response.status).toBe(400);

      // Test empty object
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({});
      expect(response.status).toBe(400);

      // Verify no users were created
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(0);
    });
  });
});