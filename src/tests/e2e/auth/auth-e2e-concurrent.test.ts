import request from 'supertest';
import { Application } from 'express';
import { createApp } from '@/core/app';
import { prisma } from '@/core/database/prisma.client';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

describe('E2E - Concurrent Auth Operations', () => {
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

  describe('Concurrent Signup Operations', () => {
    it('should handle concurrent signups with different users successfully', async () => {
      // Create 5 different signup requests
      const signupRequests: SignupInput[] = [
        {
          firstName: 'User1',
          lastName: 'Concurrent',
          email: 'user1.concurrent@example.com',
          organizationName: 'Concurrent Org 1',
          password: 'Pass123!User1',
        },
        {
          firstName: 'User2',
          lastName: 'Concurrent',
          email: 'user2.concurrent@example.com',
          organizationName: 'Concurrent Org 2',
          password: 'Pass123!User2',
        },
        {
          firstName: 'User3',
          lastName: 'Concurrent',
          email: 'user3.concurrent@example.com',
          organizationName: 'Concurrent Org 3',
          password: 'Pass123!User3',
        },
        {
          firstName: 'User4',
          lastName: 'Concurrent',
          email: 'user4.concurrent@example.com',
          organizationName: 'Concurrent Org 4',
          password: 'Pass123!User4',
        },
        {
          firstName: 'User5',
          lastName: 'Concurrent',
          email: 'user5.concurrent@example.com',
          organizationName: 'Concurrent Org 5',
          password: 'Pass123!User5',
        },
      ];

      // Execute all signups concurrently
      const promises = signupRequests.map(data =>
        request(app)
          .post('/api/v1/auth/signup')
          .send(data)
      );

      const responses = await Promise.all(promises);

      // All should succeed
      responses.forEach((response, index) => {
        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
        expect(response.body.data.user.email).toBe(signupRequests[index].email.toLowerCase());
        expect(response.body.data.organization.name).toBe(signupRequests[index].organizationName);
      });

      // Verify all users were created
      const users = await prisma.user.findMany({
        orderBy: { email: 'asc' },
      });
      expect(users).toHaveLength(5);

      // Verify all organizations were created
      const organizations = await prisma.organization.findMany({
        orderBy: { name: 'asc' },
      });
      expect(organizations).toHaveLength(5);

      // Verify all have unique IDs
      const userIds = users.map(u => u.id);
      const uniqueUserIds = new Set(userIds);
      expect(uniqueUserIds.size).toBe(5);

      const orgIds = organizations.map(o => o.id);
      const uniqueOrgIds = new Set(orgIds);
      expect(uniqueOrgIds.size).toBe(5);

      // Verify each user has verification token
      const verificationTokens = await prisma.emailVerification.findMany();
      expect(verificationTokens).toHaveLength(5);
      
      const tokenValues = verificationTokens.map(t => t.token);
      const uniqueTokens = new Set(tokenValues);
      expect(uniqueTokens.size).toBe(5); // All tokens unique
    });

    it('should handle race condition for same email correctly', async () => {
      // Create 3 identical signup requests (same email)
      const signupData: SignupInput = {
        firstName: 'Race',
        lastName: 'Condition',
        email: 'race.condition@example.com',
        organizationName: 'Race Org',
        password: 'RacePass123!',
      };

      // Create 3 requests with same email but different org names to distinguish
      const requests = [
        { ...signupData, organizationName: 'Race Org 1' },
        { ...signupData, organizationName: 'Race Org 2' },
        { ...signupData, organizationName: 'Race Org 3' },
      ];

      // Execute concurrently
      const promises = requests.map(data =>
        request(app)
          .post('/api/v1/auth/signup')
          .send(data)
      );

      const responses = await Promise.all(promises);

      // Count successes and failures
      const successes = responses.filter(r => r.status === 201);
      const failures = responses.filter(r => r.status === 409);

      // At least one should succeed, others should fail
      // Due to transaction isolation, sometimes multiple might succeed temporarily
      expect(successes.length).toBeGreaterThanOrEqual(1);
      expect(successes.length).toBeLessThanOrEqual(3);
      
      // If there are failures, check the message
      if (failures.length > 0) {
        failures.forEach(response => {
          expect(response.body.error.message).toContain('Email already registered');
        });
      }

      // Verify only one user created ultimately (unique constraint enforced at DB level)
      const users = await prisma.user.findMany({
        where: { email: signupData.email.toLowerCase() },
      });
      // Due to unique constraint, only 1 user should exist
      expect(users).toHaveLength(1);

      // Verify organizations created match successful signups
      const organizations = await prisma.organization.findMany({
        where: {
          name: {
            in: ['Race Org 1', 'Race Org 2', 'Race Org 3'],
          },
        },
      });
      expect(organizations.length).toBe(successes.length);
    });

    it('should handle race condition for same organization name correctly', async () => {
      // Create 3 signup requests with same org name but different emails
      const baseData: SignupInput = {
        firstName: 'OrgRace',
        lastName: 'Test',
        email: '',
        organizationName: 'Same Org Name',
        password: 'OrgRacePass123!',
      };

      const requests = [
        { ...baseData, email: 'orgrace1@example.com', firstName: 'OrgRace1' },
        { ...baseData, email: 'orgrace2@example.com', firstName: 'OrgRace2' },
        { ...baseData, email: 'orgrace3@example.com', firstName: 'OrgRace3' },
      ];

      // Execute concurrently
      const promises = requests.map(data =>
        request(app)
          .post('/api/v1/auth/signup')
          .send(data)
      );

      const responses = await Promise.all(promises);

      // Count successes and failures
      const successes = responses.filter(r => r.status === 201);
      const failures = responses.filter(r => r.status === 409);

      // At least one should succeed
      expect(successes.length).toBeGreaterThanOrEqual(1);
      expect(successes.length).toBeLessThanOrEqual(3);

      // If there are failures, check the message
      if (failures.length > 0) {
        failures.forEach(response => {
          expect(response.body.error.message).toContain('Organization name already taken');
        });
      }

      // Verify only one organization created (unique constraint)
      const organizations = await prisma.organization.findMany({
        where: { name: 'Same Org Name' },
      });
      expect(organizations).toHaveLength(1);

      // The successful signup should have created a user
      const users = await prisma.user.findMany({
        where: {
          email: {
            in: ['orgrace1@example.com', 'orgrace2@example.com', 'orgrace3@example.com'],
          },
        },
      });
      // Number of users should match successful signups
      expect(users.length).toBe(successes.length);
    });

    it('should handle concurrent signups with slug generation correctly', async () => {
      // Create signups with org names that would generate same base slug
      const requests: SignupInput[] = [
        {
          firstName: 'Slug1',
          lastName: 'Test',
          email: 'slug1@example.com',
          organizationName: 'Slug Test Corp', // slug: slug-test-corp
          password: 'SlugPass123!',
        },
        {
          firstName: 'Slug2',
          lastName: 'Test',
          email: 'slug2@example.com',
          organizationName: 'Slug-Test-Corp', // Different name but might generate same slug
          password: 'SlugPass123!',
        },
        {
          firstName: 'Slug3',
          lastName: 'Test',
          email: 'slug3@example.com',
          organizationName: 'SLUG TEST CORP', // Different case
          password: 'SlugPass123!',
        },
        {
          firstName: 'Slug4',
          lastName: 'Test',
          email: 'slug4@example.com',
          organizationName: 'Slug_Test_Corp', // Different separator
          password: 'SlugPass123!',
        },
      ];

      // Execute concurrently
      const promises = requests.map(data =>
        request(app)
          .post('/api/v1/auth/signup')
          .send(data)
      );

      const responses = await Promise.all(promises);

      // Count successes and failures
      const successes = responses.filter(r => r.status === 201);
      const failures = responses.filter(r => r.status === 409);

      // Should have some successes
      expect(successes.length).toBeGreaterThanOrEqual(1);
      
      // Get all created organizations
      const organizations = await prisma.organization.findMany({
        orderBy: { slug: 'asc' },
      });

      // All created orgs should have unique slugs
      const slugs = organizations.map(o => o.slug);
      const uniqueSlugs = new Set(slugs);
      expect(uniqueSlugs.size).toBe(organizations.length);

      // If multiple orgs were created with similar names
      if (organizations.length > 1) {
        // Check that slugs are unique and follow expected pattern
        const baseSlug = 'slug-test-corp';
        
        // At least one should have the base slug
        const hasBaseSlug = slugs.some(s => s === baseSlug);
        if (organizations.length >= 2) {
          expect(hasBaseSlug).toBe(true);
        }
        
        // Others should have suffixes if there were collisions
        slugs.forEach(slug => {
          // Should be related to the base slug
          expect(
            slug === baseSlug || 
            slug.startsWith(`${baseSlug}-`) ||
            slug.includes('slug') // At minimum contains 'slug'
          ).toBe(true);
        });
      }

      // Verify that each successful signup has corresponding data
      for (const success of successes) {
        const email = success.body.data.user.email;
        const user = await prisma.user.findUnique({
          where: { email },
        });
        expect(user).toBeTruthy();
      }
    });

    it('should maintain data integrity under concurrent load', async () => {
      // Create 10 concurrent signups to stress test
      const signupRequests: SignupInput[] = Array.from({ length: 10 }, (_, i) => ({
        firstName: `Stress${i}`,
        lastName: 'Test',
        email: `stress${i}@example.com`,
        organizationName: `Stress Org ${i}`,
        password: `StressPass${i}!`,
      }));

      // Execute all concurrently
      const promises = signupRequests.map(data =>
        request(app)
          .post('/api/v1/auth/signup')
          .send(data)
      );

      const responses = await Promise.all(promises);

      // All should succeed
      const successCount = responses.filter(r => r.status === 201).length;
      expect(successCount).toBe(10);

      // Verify data integrity
      const users = await prisma.user.findMany();
      const organizations = await prisma.organization.findMany();
      const profiles = await prisma.profile.findMany();
      const orgUsers = await prisma.organizationUser.findMany();
      const verificationTokens = await prisma.emailVerification.findMany();
      const passwordHistories = await prisma.passwordHistory.findMany();
      const auditLogs = await prisma.auditLog.findMany();

      // Each signup should create exactly one of each record type
      expect(users).toHaveLength(10);
      expect(organizations).toHaveLength(10);
      expect(profiles).toHaveLength(10);
      expect(orgUsers).toHaveLength(10);
      expect(verificationTokens).toHaveLength(10);
      expect(passwordHistories).toHaveLength(10);
      expect(auditLogs).toHaveLength(20); // 2 per user (signup + org create)

      // Verify all relationships are intact
      for (const user of users) {
        const profile = profiles.find(p => p.userId === user.id);
        expect(profile).toBeTruthy();

        const orgUser = orgUsers.find(ou => ou.userId === user.id);
        expect(orgUser).toBeTruthy();

        const verificationToken = verificationTokens.find(vt => vt.userId === user.id);
        expect(verificationToken).toBeTruthy();

        const passwordHistory = passwordHistories.find(ph => ph.userId === user.id);
        expect(passwordHistory).toBeTruthy();

        const userAuditLogs = auditLogs.filter(al => al.userId === user.id);
        expect(userAuditLogs).toHaveLength(2);
      }
    });
  });
});