import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

describe('Auth Integration - Signup Duplicates', () => {
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

  describe('POST /api/v1/auth/signup - Duplicate Checking', () => {
    it('should return 409 for duplicate email', async () => {
      // First, create a user successfully
      const firstUserData: SignupInput = {
        firstName: 'John',
        lastName: 'Original',
        email: 'duplicate.test@example.com',
        organizationName: 'Original Company',
        password: 'ValidPass123!',
      };

      let response = await request(app)
        .post('/api/v1/auth/signup')
        .send(firstUserData);

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);

      // Verify user was created
      const firstUser = await prisma.user.findUnique({
        where: { email: firstUserData.email.toLowerCase() }
      });
      expect(firstUser).toBeTruthy();

      // Try to create another user with same email (case insensitive)
      const duplicateEmailData: SignupInput = {
        firstName: 'Jane',
        lastName: 'Duplicate',
        email: 'DUPLICATE.TEST@EXAMPLE.COM', // Different case
        organizationName: 'Different Company',
        password: 'AnotherPass456!',
      };

      response = await request(app)
        .post('/api/v1/auth/signup')
        .send(duplicateEmailData);

      expect(response.status).toBe(409);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('email');
      expect(response.body.error.message.toLowerCase()).toContain('already');

      // Verify only one user exists
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(1);
      expect(users[0].email).toBe(firstUserData.email.toLowerCase());

      // Try again with exact same email (lowercase)
      const exactDuplicateData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Another',
        email: firstUserData.email,
        organizationName: 'Yet Another Company',
        password: 'YetAnotherPass789!',
      };

      response = await request(app)
        .post('/api/v1/auth/signup')
        .send(exactDuplicateData);

      expect(response.status).toBe(409);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Verify still only one user exists
      const finalUsers = await prisma.user.findMany();
      expect(finalUsers).toHaveLength(1);

      // Verify no additional organizations were created
      const organizations = await prisma.organization.findMany();
      expect(organizations).toHaveLength(1);
      expect(organizations[0].name).toBe(firstUserData.organizationName);
    });

    it('should return 409 for duplicate organization name', async () => {
      // First, create a user with an organization successfully
      const firstUserData: SignupInput = {
        firstName: 'Alice',
        lastName: 'Founder',
        email: 'alice@techcorp.com',
        organizationName: 'TechCorp International',
        password: 'SecurePass123!',
      };

      let response = await request(app)
        .post('/api/v1/auth/signup')
        .send(firstUserData);

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);

      // Verify organization was created
      const firstOrg = await prisma.organization.findFirst({
        where: { name: firstUserData.organizationName }
      });
      expect(firstOrg).toBeTruthy();

      // Try to create another user with same organization name (exact match)
      const duplicateOrgData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Impostor',
        email: 'bob@different.com',
        organizationName: 'TechCorp International', // Exact same name
        password: 'DifferentPass456!',
      };

      response = await request(app)
        .post('/api/v1/auth/signup')
        .send(duplicateOrgData);

      expect(response.status).toBe(409);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('organization');
      expect(response.body.error.message.toLowerCase()).toContain('already');

      // Verify only one organization exists
      const organizations = await prisma.organization.findMany();
      expect(organizations).toHaveLength(1);
      expect(organizations[0].name).toBe(firstUserData.organizationName);

      // Verify only one user exists
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(1);
      expect(users[0].email).toBe(firstUserData.email.toLowerCase());

      // Try with slightly different case (should still be duplicate)
      const differentCaseOrgData: SignupInput = {
        firstName: 'Charlie',
        lastName: 'Another',
        email: 'charlie@example.com',
        organizationName: 'TECHCORP INTERNATIONAL', // Different case
        password: 'AnotherPass789!',
      };

      response = await request(app)
        .post('/api/v1/auth/signup')
        .send(differentCaseOrgData);

      // Note: This might pass or fail depending on case sensitivity setting
      // If it passes (201), it means org names are case-sensitive
      // If it fails (409), it means org names are case-insensitive
      // Both are valid implementations
      if (response.status === 409) {
        expect(response.body.error.message.toLowerCase()).toContain('organization');
      } else if (response.status === 201) {
        // Case-sensitive implementation - different case is allowed
        expect(response.body).toHaveProperty('success', true);
        
        // Verify two organizations exist with different cases
        const finalOrgs = await prisma.organization.findMany();
        expect(finalOrgs).toHaveLength(2);
      }

      // Test that different organization names work fine
      const differentOrgData: SignupInput = {
        firstName: 'Diana',
        lastName: 'NewCo',
        email: 'diana@newcompany.com',
        organizationName: 'Completely Different Corp',
        password: 'NewCoPass123!',
      };

      response = await request(app)
        .post('/api/v1/auth/signup')
        .send(differentOrgData);

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);

      // Verify the new organization was created
      const newOrg = await prisma.organization.findFirst({
        where: { name: differentOrgData.organizationName }
      });
      expect(newOrg).toBeTruthy();
    });
  });
});