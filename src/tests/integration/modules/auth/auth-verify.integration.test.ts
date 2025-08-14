import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput, EmailVerificationInput } from '@/modules/auth/validators/auth.schema';
import jwt from 'jsonwebtoken';
import { env } from '@/core/config/env';

describe('Auth Integration - Verify Endpoint', () => {
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

  describe('POST /api/v1/auth/verify - Success Flow', () => {
    it('should successfully verify email with valid token', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.verify@example.com',
        organizationName: 'Verify Test Org',
        password: 'SecurePass123!',
      };

      const signupResponse = await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      expect(signupResponse.status).toBe(201);

      // Step 2: Get the verification token from database
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });
      expect(emailVerification).toBeTruthy();
      const verificationToken = emailVerification!.token;

      // Step 3: Verify the email using the token
      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send(verifyData)
        .expect('Content-Type', /json/);

      // Step 4: Assert the response
      expect(verifyResponse.status).toBe(200);
      expect(verifyResponse.body).toHaveProperty('success', true);
      expect(verifyResponse.body).toHaveProperty('data');

      const { data } = verifyResponse.body;
      
      // Check for JWT tokens
      expect(data).toHaveProperty('accessToken');
      expect(data).toHaveProperty('refreshToken');
      expect(data.accessToken).toBeTruthy();
      expect(data.refreshToken).toBeTruthy();
      
      // Validate access token is a valid JWT
      expect(data.accessToken).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
      
      // Decode and verify access token structure
      const decoded = jwt.decode(data.accessToken) as any;
      expect(decoded).toBeTruthy();
      expect(decoded).toHaveProperty('userId');
      expect(decoded).toHaveProperty('email', signupData.email.toLowerCase());
      expect(decoded).toHaveProperty('organizationId');
      expect(decoded).toHaveProperty('sessionId');
      expect(decoded).toHaveProperty('iat');
      expect(decoded).toHaveProperty('exp');
      
      // Check user data in response
      expect(data).toHaveProperty('user');
      expect(data.user).toHaveProperty('id');
      expect(data.user).toHaveProperty('email', signupData.email.toLowerCase());
      expect(data.user).toHaveProperty('firstName', signupData.firstName);
      expect(data.user).toHaveProperty('lastName', signupData.lastName);
      
      // Check organization data in response
      expect(data).toHaveProperty('organization');
      expect(data.organization).toHaveProperty('id');
      expect(data.organization).toHaveProperty('name', signupData.organizationName);
      expect(data.organization).toHaveProperty('slug');
      
      // Step 5: Verify database state changes
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() }
      });
      
      expect(user).toBeTruthy();
      expect(user!.status).toBe('ACTIVE');
      expect(user!.emailVerified).toBe(true);
      expect(user!.emailVerifiedAt).toBeInstanceOf(Date);
      
      // Verify the token was deleted
      const deletedToken = await prisma.emailVerification.findFirst({
        where: { token: verificationToken }
      });
      expect(deletedToken).toBeNull();
    });

    it('should create session and refresh token after verification', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.session@example.com',
        organizationName: 'Session Test Corp',
        password: 'StrongPass456!',
      };

      await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Step 2: Get the verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });
      const verificationToken = emailVerification!.token;

      // Verify no session exists before verification
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() }
      });
      const sessionsBefore = await prisma.session.findMany({
        where: { userId: user!.id }
      });
      expect(sessionsBefore).toHaveLength(0);

      const refreshTokensBefore = await prisma.refreshToken.findMany({
        where: { userId: user!.id }
      });
      expect(refreshTokensBefore).toHaveLength(0);

      // Step 3: Verify the email
      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .set('User-Agent', 'Jest Test Agent')
        .set('X-Forwarded-For', '192.168.1.100')
        .send(verifyData);

      expect(verifyResponse.status).toBe(200);
      const { refreshToken: returnedRefreshToken } = verifyResponse.body.data;

      // Step 4: Check session was created
      const sessionsAfter = await prisma.session.findMany({
        where: { userId: user!.id }
      });

      expect(sessionsAfter).toHaveLength(1);
      const session = sessionsAfter[0];
      
      // Verify session properties
      expect(session.userId).toBe(user!.id);
      expect(session.isExpired).toBe(false); // Should not be expired
      expect(session.ipAddress).toBeTruthy(); // Should capture IP
      expect(session.userAgent).toContain('Jest Test Agent');
      expect(session.expiresAt).toBeInstanceOf(Date);
      expect(session.token).toBeTruthy(); // Session has its own token
      
      // Verify session expiry is in the future (approximately 24 hours)
      const now = new Date();
      const expiryTime = session.expiresAt.getTime();
      expect(expiryTime).toBeGreaterThan(now.getTime());
      const twentyFourHoursFromNow = now.getTime() + 24 * 60 * 60 * 1000;
      expect(Math.abs(expiryTime - twentyFourHoursFromNow)).toBeLessThan(60000); // Within 1 minute

      // Step 5: Check refresh token was created
      const refreshTokensAfter = await prisma.refreshToken.findMany({
        where: { userId: user!.id }
      });

      expect(refreshTokensAfter).toHaveLength(1);
      const refreshToken = refreshTokensAfter[0];
      
      // Verify refresh token properties
      expect(refreshToken.userId).toBe(user!.id);
      expect(refreshToken.token).toBe(returnedRefreshToken);
      expect(refreshToken.isRevoked).toBe(false); // Should not be revoked
      expect(refreshToken.expiresAt).toBeInstanceOf(Date);
      expect(refreshToken.family).toBeTruthy(); // Should have a family ID for rotation
      
      // Verify refresh token expiry is in the future (should be longer than session)
      const refreshExpiryTime = refreshToken.expiresAt.getTime();
      expect(refreshExpiryTime).toBeGreaterThan(expiryTime); // Refresh token expires after session
      
      // Verify both tokens belong to same user
      expect(session.userId).toBe(refreshToken.userId);
    });

    it('should update user status to ACTIVE', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob.status@example.com',
        organizationName: 'Status Check Inc',
        password: 'SecurePass789!',
      };

      await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Step 2: Verify user status is PENDING before verification
      const userBefore = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() }
      });
      
      expect(userBefore).toBeTruthy();
      expect(userBefore!.status).toBe('PENDING');
      expect(userBefore!.emailVerified).toBe(false);
      expect(userBefore!.emailVerifiedAt).toBeNull();

      // Step 3: Get the verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });
      const verificationToken = emailVerification!.token;

      // Step 4: Verify the email
      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send(verifyData);

      expect(verifyResponse.status).toBe(200);

      // Step 5: Check user status was updated to ACTIVE
      const userAfter = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() }
      });

      expect(userAfter).toBeTruthy();
      expect(userAfter!.status).toBe('ACTIVE'); // Status should be updated
      expect(userAfter!.emailVerified).toBe(true); // Email should be verified
      expect(userAfter!.emailVerifiedAt).toBeInstanceOf(Date); // Timestamp should be set
      
      // Verify the timestamp is recent (within last minute)
      const verifiedAt = userAfter!.emailVerifiedAt!.getTime();
      const now = new Date().getTime();
      expect(verifiedAt).toBeLessThanOrEqual(now);
      expect(now - verifiedAt).toBeLessThan(60000); // Within 1 minute
      
      // Verify other user fields remained unchanged
      expect(userAfter!.email).toBe(signupData.email.toLowerCase());
      expect(userAfter!.id).toBe(userBefore!.id);
      expect(userAfter!.passwordHash).toBe(userBefore!.passwordHash);
    });

    it('should delete verification token after use', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Alice',
        lastName: 'Token',
        email: 'alice.token@example.com',
        organizationName: 'Token Test LLC',
        password: 'TokenPass123!',
      };

      await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Step 2: Get the verification token
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });
      
      expect(emailVerification).toBeTruthy();
      const verificationToken = emailVerification!.token;
      const verificationId = emailVerification!.id;

      // Verify token exists before verification
      const tokenBefore = await prisma.emailVerification.findUnique({
        where: { id: verificationId }
      });
      expect(tokenBefore).toBeTruthy();
      expect(tokenBefore!.token).toBe(verificationToken);

      // Step 3: Verify the email
      const verifyData: EmailVerificationInput = {
        token: verificationToken,
      };

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send(verifyData);

      expect(verifyResponse.status).toBe(200);

      // Step 4: Check token was deleted
      const tokenAfterById = await prisma.emailVerification.findUnique({
        where: { id: verificationId }
      });
      expect(tokenAfterById).toBeNull(); // Token should be deleted by ID

      const tokenAfterByToken = await prisma.emailVerification.findUnique({
        where: { token: verificationToken }
      });
      expect(tokenAfterByToken).toBeNull(); // Token should be deleted by token value

      const tokenAfterByEmail = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });
      expect(tokenAfterByEmail).toBeNull(); // No token should exist for this email

      // Step 5: Verify all verification tokens for user are gone
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() }
      });
      
      const allUserTokens = await prisma.emailVerification.findMany({
        where: { userId: user!.id }
      });
      expect(allUserTokens).toHaveLength(0); // No tokens should remain for this user
    });

    it('should validate JWT claims match database records', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'JWT',
        lastName: 'Claims',
        email: 'jwt.claims@example.com',
        organizationName: 'JWT Claims Corp',
        password: 'JWTPass123!',
      };

      await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Get user and organization from database
      const user = await prisma.user.findUnique({
        where: { email: signupData.email.toLowerCase() },
        include: {
          organizationUsers: {
            include: { organization: true }
          }
        }
      });
      const organization = user!.organizationUsers[0].organization;

      // Step 2: Get verification token and verify
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send({ token: emailVerification!.token });

      expect(verifyResponse.status).toBe(200);
      const { accessToken } = verifyResponse.body.data;

      // Step 3: Decode JWT and validate all claims
      const decoded = jwt.decode(accessToken) as any;
      
      // Validate required claims exist
      expect(decoded).toHaveProperty('userId');
      expect(decoded).toHaveProperty('email');
      expect(decoded).toHaveProperty('organizationId');
      expect(decoded).toHaveProperty('sessionId');
      expect(decoded).toHaveProperty('iat');
      expect(decoded).toHaveProperty('exp');
      expect(decoded).toHaveProperty('jti');
      
      // Validate claims match database records
      expect(decoded.userId).toBe(user!.id);
      expect(decoded.email).toBe(user!.email);
      expect(decoded.organizationId).toBe(organization.id);
      
      // Validate session exists and matches
      const session = await prisma.session.findFirst({
        where: { userId: user!.id }
      });
      expect(decoded.sessionId).toBe(session!.id);
      
      // Validate timestamps
      const now = Math.floor(Date.now() / 1000);
      expect(decoded.iat).toBeLessThanOrEqual(now);
      expect(decoded.iat).toBeGreaterThan(now - 10); // Issued within last 10 seconds
      expect(decoded.exp).toBeGreaterThan(now); // Not expired
      expect(decoded.exp - decoded.iat).toBe(60 * 60); // 1 hour expiry (as per JWT_EXPIRES_IN=1h)
      
      // Validate jti is a UUID
      expect(decoded.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      
      // Step 4: Verify token with secret
      const verified = jwt.verify(accessToken, env.JWT_SECRET as string) as any;
      expect(verified).toBeTruthy();
      expect(verified.userId).toBe(decoded.userId);
      expect(verified.email).toBe(decoded.email);
    });

    it('should generate JWT with valid structure', async () => {
      // Step 1: Create a user through signup
      const signupData: SignupInput = {
        firstName: 'Structure',
        lastName: 'Test',
        email: 'jwt.structure@example.com',
        organizationName: 'JWT Structure Corp',
        password: 'StructPass123!',
      };

      await request(app)
        .post('/api/v1/auth/signup')
        .send(signupData);

      // Step 2: Get verification token and verify
      const emailVerification = await prisma.emailVerification.findFirst({
        where: { email: signupData.email.toLowerCase() }
      });

      const verifyResponse = await request(app)
        .post('/api/v1/auth/verify')
        .send({ token: emailVerification!.token });

      expect(verifyResponse.status).toBe(200);
      const { accessToken, refreshToken } = verifyResponse.body.data;

      // Step 3: Validate JWT structure (header.payload.signature)
      const parts = accessToken.split('.');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBeTruthy(); // Header
      expect(parts[1]).toBeTruthy(); // Payload
      expect(parts[2]).toBeTruthy(); // Signature
      
      // Step 4: Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      expect(header).toHaveProperty('alg');
      expect(header.alg).toBe('HS256'); // Default algorithm for jsonwebtoken
      expect(header).toHaveProperty('typ');
      expect(header.typ).toBe('JWT');
      
      // Step 5: Decode and validate payload structure
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      expect(payload).toBeTruthy();
      expect(typeof payload).toBe('object');
      
      // Validate required JWT claims
      expect(payload).toHaveProperty('userId');
      expect(payload).toHaveProperty('email');
      expect(payload).toHaveProperty('organizationId');
      expect(payload).toHaveProperty('sessionId');
      expect(payload).toHaveProperty('iat');
      expect(payload).toHaveProperty('exp');
      expect(payload).toHaveProperty('jti');
      
      // Validate claim types
      expect(typeof payload.userId).toBe('string');
      expect(typeof payload.email).toBe('string');
      expect(typeof payload.organizationId).toBe('string');
      expect(typeof payload.sessionId).toBe('string');
      expect(typeof payload.iat).toBe('number');
      expect(typeof payload.exp).toBe('number');
      expect(typeof payload.jti).toBe('string');
      
      // Step 6: Validate signature exists and is base64url encoded
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/); // Base64url characters only
      expect(parts[2].length).toBeGreaterThan(0);
      
      // Step 7: Validate refresh token structure (UUID v4)
      expect(refreshToken).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      
      // Step 8: Verify entire token can be verified without errors
      expect(() => jwt.verify(accessToken, env.JWT_SECRET as string)).not.toThrow();
    });
  });
});