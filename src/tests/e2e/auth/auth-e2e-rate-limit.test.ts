import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';

describe('E2E - Rate Limiting', () => {
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

  describe('Global Rate Limiting', () => {
    it('should enforce rate limit of 100 requests per minute', async () => {
      // Send 100 requests concurrently in batches to speed up test
      const batchSize = 10;
      const totalRequests = 100;

      for (let batch = 0; batch < totalRequests / batchSize; batch++) {
        const promises = [];
        for (let i = 0; i < batchSize; i++) {
          const index = batch * batchSize + i;
          promises.push(
            request(app)
              .post('/api/v1/auth/signup')
              .send({
                firstName: `RateTest${index}`,
                lastName: 'User',
                email: `ratetest${index}@example.com`,
                organizationName: `Rate Test Org ${index}`,
                password: `RatePass${index}!`,
              }),
          );
        }

        const batchResponses = await Promise.all(promises);

        // All first 100 should not be rate limited
        batchResponses.forEach((response) => {
          expect(response.status).not.toBe(429);
        });
      }

      // The 101st request should be rate limited
      const rateLimitedResponse = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'RateLimit',
        lastName: 'Exceeded',
        email: 'ratelimit@example.com',
        organizationName: 'Rate Limited Org',
        password: 'RateLimitPass123!',
      });

      expect(rateLimitedResponse.status).toBe(429);
      expect(rateLimitedResponse.body.error.message).toContain('Too many requests');

      // Verify we created users
      const users = await prisma.user.findMany();
      expect(users.length).toBeLessThanOrEqual(100);
    }, 20000); // Increase timeout for this test

    it('should include rate limit headers in responses', async () => {
      // Send a request and check for rate limit headers
      const response = await request(app).post('/api/v1/auth/signup').send({
        firstName: 'Header',
        lastName: 'Test',
        email: 'header.test@example.com',
        organizationName: 'Header Test Org',
        password: 'HeaderPass123!',
      });

      // Check for standard rate limit headers
      expect(response.headers).toHaveProperty('ratelimit-limit');
      expect(response.headers).toHaveProperty('ratelimit-remaining');
      expect(response.headers).toHaveProperty('ratelimit-reset');

      // Verify header values
      const limit = parseInt(response.headers['ratelimit-limit']);
      const remaining = parseInt(response.headers['ratelimit-remaining']);

      expect(limit).toBe(100); // Global limit is 100
      expect(remaining).toBeLessThan(100); // Should have used at least 1
      expect(remaining).toBeGreaterThanOrEqual(0);
    });

    it('should rate limit per IP address', async () => {
      // Send 50 requests from IP 1 in batches
      const batchSize = 10;
      const requestsPerIP = 50;

      // IP 1 requests
      for (let batch = 0; batch < requestsPerIP / batchSize; batch++) {
        const promises = [];
        for (let i = 0; i < batchSize; i++) {
          const index = batch * batchSize + i;
          promises.push(
            request(app)
              .post('/api/v1/auth/signup')
              .set('X-Forwarded-For', '192.168.1.1')
              .send({
                firstName: `IP1User${index}`,
                lastName: 'Test',
                email: `ip1user${index}@example.com`,
                organizationName: `IP1 Org ${index}`,
                password: `IP1Pass${index}!`,
              }),
          );
        }

        const batchResponses = await Promise.all(promises);
        batchResponses.forEach((response) => {
          expect(response.status).not.toBe(429);
        });
      }

      // IP 2 requests
      for (let batch = 0; batch < requestsPerIP / batchSize; batch++) {
        const promises = [];
        for (let i = 0; i < batchSize; i++) {
          const index = batch * batchSize + i;
          promises.push(
            request(app)
              .post('/api/v1/auth/signup')
              .set('X-Forwarded-For', '192.168.1.2')
              .send({
                firstName: `IP2User${index}`,
                lastName: 'Test',
                email: `ip2user${index}@example.com`,
                organizationName: `IP2 Org ${index}`,
                password: `IP2Pass${index}!`,
              }),
          );
        }

        const batchResponses = await Promise.all(promises);
        batchResponses.forEach((response) => {
          expect(response.status).not.toBe(429);
        });
      }

      // 51st request from IP 2 should NOT be rate limited (different IP)
      const ip2ExtraResponse = await request(app)
        .post('/api/v1/auth/signup')
        .set('X-Forwarded-For', '192.168.1.2')
        .send({
          firstName: 'IP2Extra',
          lastName: 'User',
          email: 'ip2extra@example.com',
          organizationName: 'IP2 Extra Org',
          password: 'IP2ExtraPass123!',
        });

      // IP2 should still have requests remaining
      expect(ip2ExtraResponse.status).not.toBe(429);
    }, 20000); // Increase timeout

    it('should return proper error structure for rate limited requests', async () => {
      // First exhaust the rate limit
      const promises = [];
      for (let i = 0; i < 101; i++) {
        promises.push(
          request(app)
            .post('/api/v1/auth/signup')
            .set('X-Forwarded-For', '10.0.0.1') // Use unique IP for this test
            .send({
              firstName: `Exhaust${i}`,
              lastName: 'Limit',
              email: `exhaust${i}@example.com`,
              organizationName: `Exhaust Org ${i}`,
              password: `ExhaustPass${i}!`,
            }),
        );
      }

      const responses = await Promise.all(promises);

      // Find the rate limited response(s)
      const rateLimited = responses.filter((r) => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);

      // Check the error structure
      const rateLimitedResponse = rateLimited[0];
      expect(rateLimitedResponse.body).toHaveProperty('error');
      expect(rateLimitedResponse.body.error).toHaveProperty('message');
      expect(rateLimitedResponse.body.error).toHaveProperty('statusCode', 429);
      expect(rateLimitedResponse.body.error.message).toContain('Too many requests from this IP');
    });

    it('should not rate limit health check endpoints', async () => {
      // Health checks should be excluded from rate limiting
      const healthPromises = [];

      // Send 150 health check requests (more than the limit)
      for (let i = 0; i < 150; i++) {
        healthPromises.push(
          request(app).get('/health').set('X-Forwarded-For', '10.0.0.2'), // Use unique IP
        );
      }

      const healthResponses = await Promise.all(healthPromises);

      // All health checks should succeed
      healthResponses.forEach((response) => {
        expect(response.status).toBe(200);
        expect(response.status).not.toBe(429);
      });

      // Now test that regular endpoints are still rate limited for this IP
      const regularPromises = [];
      for (let i = 0; i < 101; i++) {
        regularPromises.push(
          request(app)
            .get('/api/v1') // Regular API endpoint
            .set('X-Forwarded-For', '10.0.0.2'),
        );
      }

      const regularResponses = await Promise.all(regularPromises);

      // Should have some rate limited responses
      const rateLimited = regularResponses.filter((r) => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });
});
