import { Application } from 'express';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { createApp } from '../../core/app';
import { faker } from '@faker-js/faker';

// Test database client
export const testPrisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_TEST_URL || process.env.DATABASE_URL,
    },
  },
});

// Create test app instance
export function createTestApp(): Application {
  return createApp();
}

// Request helper with common headers
export function createTestRequest(app: Application) {
  return {
    get: (url: string) => request(app).get(url).set('X-Request-Id', faker.string.uuid()),
    post: (url: string) => request(app).post(url).set('X-Request-Id', faker.string.uuid()),
    put: (url: string) => request(app).put(url).set('X-Request-Id', faker.string.uuid()),
    delete: (url: string) => request(app).delete(url).set('X-Request-Id', faker.string.uuid()),
    patch: (url: string) => request(app).patch(url).set('X-Request-Id', faker.string.uuid()),
  };
}

// Authenticated request helper
export function createAuthRequest(app: Application, token: string) {
  return {
    get: (url: string) =>
      request(app)
        .get(url)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Request-Id', faker.string.uuid()),
    post: (url: string) =>
      request(app)
        .post(url)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Request-Id', faker.string.uuid()),
    put: (url: string) =>
      request(app)
        .put(url)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Request-Id', faker.string.uuid()),
    delete: (url: string) =>
      request(app)
        .delete(url)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Request-Id', faker.string.uuid()),
    patch: (url: string) =>
      request(app)
        .patch(url)
        .set('Authorization', `Bearer ${token}`)
        .set('X-Request-Id', faker.string.uuid()),
  };
}

// Database cleanup for tests
export async function cleanDatabase() {
  const tables = await testPrisma.$queryRaw<
    Array<{ tablename: string }>
  >`SELECT tablename FROM pg_tables WHERE schemaname='public'`;

  const tableNames = tables
    .map(({ tablename }) => tablename)
    .filter((name) => name !== '_prisma_migrations')
    .map((name) => `"public"."${name}"`)
    .join(', ');

  if (tableNames.length > 0) {
    await testPrisma.$executeRawUnsafe(`TRUNCATE TABLE ${tableNames} RESTART IDENTITY CASCADE`);
  }
}

// Test data factories
export const testData = {
  user: () => ({
    email: faker.internet.email(),
    name: faker.person.fullName(),
  }),

  session: (userId: string) => ({
    token: faker.string.uuid(),
    userId,
    expiresAt: faker.date.future(),
  }),
};

// Setup and teardown helpers
export async function setupTestDatabase() {
  await testPrisma.$connect();
}

export async function teardownTestDatabase() {
  await cleanDatabase();
  await testPrisma.$disconnect();
}
