import { SignupService } from '@/modules/auth/services/signup.service';
import { prisma } from '@/core/database/prisma.client';
import { hashPassword } from '@/modules/auth/utils/password.utils';
import { generateVerificationToken } from '@/modules/auth/utils/token.utils';
import { generateOrganizationSlug } from '@/modules/shared/utils/slug.utils';
import { sendVerificationEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import { addPasswordToHistory } from '@/modules/auth/utils/password.utils';
import type { SignupInput } from '@/modules/auth/validators/auth.schema';

// Mock all dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
    },
    organization: {
      findUnique: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/modules/auth/utils/password.utils', () => ({
  hashPassword: jest.fn(),
  addPasswordToHistory: jest.fn(),
}));

jest.mock('@/modules/auth/utils/token.utils', () => ({
  generateVerificationToken: jest.fn(),
}));

jest.mock('@/modules/shared/utils/slug.utils', () => ({
  generateOrganizationSlug: jest.fn(),
}));

jest.mock('@/modules/shared/utils/email.utils', () => ({
  sendVerificationEmail: jest.fn(),
}));

jest.mock('@/modules/shared/services/audit.service', () => ({
  auditService: {
    logAction: jest.fn(),
  },
}));

describe('SignupService - Signup Validation Tests', () => {
  let signupService: SignupService;

  beforeEach(() => {
    signupService = new SignupService();
    jest.clearAllMocks();
  });

  describe('signup', () => {
    it('should generate unique organization slug', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Slug',
        lastName: 'Test',
        email: 'slug@example.com',
        organizationName: 'My Awesome Company!!!',
        password: 'SlugPass123!',
      };

      const expectedSlug = 'my-awesome-company';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock slug generation
      (generateOrganizationSlug as jest.Mock).mockResolvedValue(expectedSlug);

      // Mock other utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');

      // Mock successful transaction
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: 'user-slug-test',
              email: signupData.email,
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
          },
          organization: {
            create: jest.fn().mockImplementation((data) => {
              // Verify the slug is being used
              expect(data.data.slug).toBe(expectedSlug);

              return Promise.resolve({
                id: 'org-slug-test',
                name: signupData.organizationName,
                slug: data.data.slug,
              });
            }),
          },
          role: {
            findFirst: jest.fn().mockResolvedValue({ id: 'role-123', name: 'owner' }),
          },
          organizationUser: {
            create: jest.fn().mockResolvedValue({ id: 'org-user-123' }),
          },
          emailVerification: {
            create: jest.fn().mockResolvedValue({ id: 'email-ver-123' }),
          },
        };

        return callback(mockTx);
      });

      (prisma.$transaction as jest.Mock).mockImplementation(mockTransaction);

      // Act
      const result = await signupService.signup(signupData);

      // Assert
      expect(generateOrganizationSlug).toHaveBeenCalledWith(signupData.organizationName);
      expect(generateOrganizationSlug).toHaveBeenCalledTimes(1);
      expect(result.organization.slug).toBe(expectedSlug);
    });

    it('should generate verification token', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Token',
        lastName: 'Test',
        email: 'token@example.com',
        organizationName: 'Token Test Org',
        password: 'TokenPass123!',
      };

      const expectedToken = 'secure-verification-token-abc123def456';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock token generation
      (generateVerificationToken as jest.Mock).mockReturnValue(expectedToken);

      // Mock other utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('token-test-org');

      // Mock successful transaction
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: 'user-token-test',
              email: signupData.email,
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
          },
          organization: {
            create: jest.fn().mockResolvedValue({
              id: 'org-token-test',
              name: signupData.organizationName,
              slug: 'token-test-org',
            }),
          },
          role: {
            findFirst: jest.fn().mockResolvedValue({ id: 'role-123', name: 'owner' }),
          },
          organizationUser: {
            create: jest.fn().mockResolvedValue({ id: 'org-user-123' }),
          },
          emailVerification: {
            create: jest.fn().mockImplementation((data) => {
              // Verify the token is being stored
              expect(data.data.token).toBe(expectedToken);
              expect(data.data.expiresAt).toBeInstanceOf(Date);

              // Verify expiry is 24 hours from now
              const expiryTime = data.data.expiresAt.getTime();
              const expectedExpiry = Date.now() + 24 * 60 * 60 * 1000;
              expect(Math.abs(expiryTime - expectedExpiry)).toBeLessThan(1000); // Within 1 second

              return Promise.resolve({
                id: 'email-ver-123',
                token: data.data.token,
                expiresAt: data.data.expiresAt,
              });
            }),
          },
        };

        return callback(mockTx);
      });

      (prisma.$transaction as jest.Mock).mockImplementation(mockTransaction);

      // Act
      await signupService.signup(signupData);

      // Assert
      expect(generateVerificationToken).toHaveBeenCalled();
      expect(generateVerificationToken).toHaveBeenCalledTimes(1);

      // Verify token was sent in email
      expect(sendVerificationEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          email: signupData.email,
          firstName: signupData.firstName,
        }),
        expectedToken,
      );
    });

    it('should add password to history', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'History',
        lastName: 'Test',
        email: 'history@example.com',
        organizationName: 'History Test Org',
        password: 'HistoryPass123!',
      };

      const mockUserId = 'user-history-test';
      const mockHashedPassword = 'hashed-history-password';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (hashPassword as jest.Mock).mockResolvedValue(mockHashedPassword);
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('history-test-org');

      // Mock successful transaction
      const mockTx = {
        user: {
          create: jest.fn().mockResolvedValue({
            id: mockUserId,
            email: signupData.email,
            passwordHash: mockHashedPassword,
          }),
        },
        profile: {
          create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
        },
        organization: {
          create: jest.fn().mockResolvedValue({
            id: 'org-history-test',
            name: signupData.organizationName,
            slug: 'history-test-org',
          }),
        },
        role: {
          findFirst: jest.fn().mockResolvedValue({ id: 'role-123', name: 'owner' }),
        },
        organizationUser: {
          create: jest.fn().mockResolvedValue({ id: 'org-user-123' }),
        },
        emailVerification: {
          create: jest.fn().mockResolvedValue({ id: 'email-ver-123' }),
        },
      };

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        return callback(mockTx);
      });

      // Act
      await signupService.signup(signupData);

      // Assert
      // Verify password was hashed
      expect(hashPassword).toHaveBeenCalledWith(signupData.password);

      // Verify password history was called with correct parameters
      expect(addPasswordToHistory).toHaveBeenCalledWith(
        mockUserId,
        mockHashedPassword,
        mockTx, // Should pass the transaction context
      );
      expect(addPasswordToHistory).toHaveBeenCalledTimes(1);

      // Verify it was called after user creation (by checking the userId matches)
      const userCreateCall = mockTx.user.create.mock.calls[0][0];
      expect(userCreateCall.data.passwordHash).toBe(mockHashedPassword);
    });

    it('should create audit logs (user.signup and organization.create)', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Audit',
        lastName: 'Test',
        email: 'audit@example.com',
        organizationName: 'Audit Test Org',
        password: 'AuditPass123!',
      };

      const mockUserId = 'user-audit-test';
      const mockOrgId = 'org-audit-test';
      const ipAddress = '192.168.1.100';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('audit-test-org');

      // Mock successful transaction
      const mockTx = {
        user: {
          create: jest.fn().mockResolvedValue({
            id: mockUserId,
            email: signupData.email,
          }),
        },
        profile: {
          create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
        },
        organization: {
          create: jest.fn().mockResolvedValue({
            id: mockOrgId,
            name: signupData.organizationName,
            slug: 'audit-test-org',
          }),
        },
        role: {
          findFirst: jest.fn().mockResolvedValue({ id: 'role-123', name: 'owner' }),
        },
        organizationUser: {
          create: jest.fn().mockResolvedValue({ id: 'org-user-123' }),
        },
        emailVerification: {
          create: jest.fn().mockResolvedValue({ id: 'email-ver-123' }),
        },
      };

      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        return callback(mockTx);
      });

      // Act
      await signupService.signup(signupData, ipAddress);

      // Assert
      // Verify audit logs were created
      expect(auditService.logAction).toHaveBeenCalledTimes(2);

      // Verify user signup audit log
      expect(auditService.logAction).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          userId: mockUserId,
          action: 'user.signup',
          resource: 'user',
          resourceId: mockUserId,
          details: {
            email: signupData.email,
            firstName: signupData.firstName,
            lastName: signupData.lastName,
          },
          ipAddress,
        }),
        mockTx, // Should pass transaction context
      );

      // Verify organization creation audit log
      expect(auditService.logAction).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          userId: mockUserId,
          organizationId: mockOrgId,
          action: 'organization.create',
          resource: 'organization',
          resourceId: mockOrgId,
          details: {
            name: signupData.organizationName,
            slug: 'audit-test-org',
          },
          ipAddress,
        }),
        mockTx, // Should pass transaction context
      );
    });
  });
});
