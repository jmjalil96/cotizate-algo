import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

describe('Auth Integration - Signup Validation', () => {
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

  describe('POST /api/v1/auth/signup - Validation', () => {
    it('should validate email format', async () => {
      // Test invalid email without @
      let response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'invalidemail',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test invalid email without domain
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test invalid email without local part
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: '@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test email with spaces
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test user@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test email with invalid characters
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test<user>@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test double @ in email
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('email');

      // Test empty string as email
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: '',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error).toBeTruthy();
      expect(response.body.error.message).toBeTruthy();

      // Verify no users were created with invalid emails
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(0);

      // Test valid email passes (control test)
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'valid.email@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);

      // Verify user was created with valid email
      const validUser = await prisma.user.findUnique({
        where: { email: 'valid.email@example.com' },
      });
      expect(validUser).toBeTruthy();
    });

    it('should validate password strength', async () => {
      // Test password too short (less than 8 chars)
      let response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@example.com',
        organizationName: 'Test Org',
        password: 'Pass1!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Test password without uppercase letter
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test2@example.com',
        organizationName: 'Test Org',
        password: 'password123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Test password without lowercase letter
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test3@example.com',
        organizationName: 'Test Org',
        password: 'PASSWORD123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Test password without number
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test4@example.com',
        organizationName: 'Test Org',
        password: 'Password!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Test password without special character
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test5@example.com',
        organizationName: 'Test Org',
        password: 'Password123',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Test empty password
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test6@example.com',
        organizationName: 'Test Org',
        password: '',
      });

      expect(response.status).toBe(400);
      expect(response.body.error).toBeTruthy();

      // Test password with only spaces
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'test7@example.com',
        organizationName: 'Test Org',
        password: '        ',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message.toLowerCase()).toContain('password');

      // Verify no users were created with weak passwords
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(0);

      // Test valid password passes (control test)
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'strong.password@example.com',
        organizationName: 'Test Org',
        password: 'StrongPass123!',
      });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);

      // Verify user was created with strong password
      const validUser = await prisma.user.findUnique({
        where: { email: 'strong.password@example.com' },
      });
      expect(validUser).toBeTruthy();
    });

    it('should return 400 for invalid input types', async () => {
      // Test with number instead of string for firstName
      let response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 123,
        lastName: 'Doe',
        email: 'test@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with boolean for lastName
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'John',
        lastName: true,
        email: 'test2@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with array for organizationName
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test3@example.com',
          organizationName: ['Test', 'Org'],
          password: 'ValidPass123!',
        });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with object for password
      response = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test4@example.com',
          organizationName: 'Test Org',
          password: { value: 'ValidPass123!' },
        });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Test with null values
      response = await request(app).post('/api/v1/auth/signup').send({
        firstName: null,
        lastName: 'Doe',
        email: 'test5@example.com',
        organizationName: 'Test Org',
        password: 'ValidPass123!',
      });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBeTruthy();

      // Verify no users were created with invalid input types
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(0);
    });
  });
});
