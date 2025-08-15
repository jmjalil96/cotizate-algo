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

describe('SignupService - Signup Core Tests', () => {
  let signupService: SignupService;

  beforeEach(() => {
    signupService = new SignupService();
    jest.clearAllMocks();
  });

  describe('signup', () => {
    it('should successfully create user with valid data', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        organizationName: 'Test Organization',
        password: 'SecurePass123!',
      };

      const mockUserId = 'user-123';
      const mockOrgId = 'org-123';
      const mockRoleId = 'role-123';
      const mockPasswordHash = 'hashed-password';
      const mockOrgSlug = 'test-organization';
      const mockVerificationToken = 'verification-token-123';
      const ipAddress = '127.0.0.1';

      // Mock pre-checks
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (generateOrganizationSlug as jest.Mock).mockResolvedValue(mockOrgSlug);
      (hashPassword as jest.Mock).mockResolvedValue(mockPasswordHash);
      (generateVerificationToken as jest.Mock).mockReturnValue(mockVerificationToken);

      // Mock transaction
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: mockUserId,
              email: signupData.email,
              passwordHash: mockPasswordHash,
              status: 'PENDING',
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({
              id: 'profile-123',
              userId: mockUserId,
              firstName: signupData.firstName,
              lastName: signupData.lastName,
            }),
          },
          organization: {
            create: jest.fn().mockResolvedValue({
              id: mockOrgId,
              name: signupData.organizationName,
              slug: mockOrgSlug,
            }),
          },
          role: {
            findFirst: jest.fn().mockResolvedValue({
              id: mockRoleId,
              name: 'owner',
              organizationId: null,
            }),
          },
          organizationUser: {
            create: jest.fn().mockResolvedValue({
              id: 'org-user-123',
              userId: mockUserId,
              organizationId: mockOrgId,
              roleId: mockRoleId,
            }),
          },
          emailVerification: {
            create: jest.fn().mockResolvedValue({
              id: 'email-verification-123',
              userId: mockUserId,
              email: signupData.email,
              token: mockVerificationToken,
            }),
          },
        };

        return callback(mockTx);
      });

      (prisma.$transaction as jest.Mock).mockImplementation(mockTransaction);

      // Act
      const result = await signupService.signup(signupData, ipAddress);

      // Assert
      expect(result).toEqual({
        message: 'Account created successfully. Please check your email to verify your account.',
        user: {
          id: mockUserId,
          email: signupData.email,
        },
        organization: {
          id: mockOrgId,
          name: signupData.organizationName,
          slug: mockOrgSlug,
        },
      });

      // Verify pre-checks were called
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: signupData.email },
      });
      expect(prisma.organization.findUnique).toHaveBeenCalledWith({
        where: { name: signupData.organizationName },
      });

      // Verify utilities were called
      expect(generateOrganizationSlug).toHaveBeenCalledWith(signupData.organizationName);
      expect(hashPassword).toHaveBeenCalledWith(signupData.password);
      expect(generateVerificationToken).toHaveBeenCalled();

      // Verify transaction was called
      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify password history was added
      expect(addPasswordToHistory).toHaveBeenCalledWith(
        mockUserId,
        mockPasswordHash,
        expect.anything(),
      );

      // Verify audit logs were created
      expect(auditService.logAction).toHaveBeenCalledTimes(2);
      expect(auditService.logAction).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUserId,
          action: 'user.signup',
          resource: 'user',
          resourceId: mockUserId,
          ipAddress,
        }),
        expect.anything(),
      );
      expect(auditService.logAction).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUserId,
          organizationId: mockOrgId,
          action: 'organization.create',
          resource: 'organization',
          resourceId: mockOrgId,
          ipAddress,
        }),
        expect.anything(),
      );

      // Verify email was sent
      expect(sendVerificationEmail).toHaveBeenCalledWith(
        {
          email: signupData.email,
          firstName: signupData.firstName,
        },
        mockVerificationToken,
      );
    });

    it('should throw ConflictError when email already exists', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'existing@example.com',
        organizationName: 'New Organization',
        password: 'AnotherPass123!',
      };

      // Mock that email already exists
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
        id: 'existing-user-id',
        email: signupData.email,
      });

      // Act & Assert
      await expect(signupService.signup(signupData)).rejects.toThrow('Email already registered');

      // Verify that we checked for existing email
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: signupData.email },
      });

      // Verify that we didn't proceed to check organization or create anything
      expect(prisma.organization.findUnique).not.toHaveBeenCalled();
      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(hashPassword).not.toHaveBeenCalled();
      expect(generateVerificationToken).not.toHaveBeenCalled();
      expect(sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('should throw ConflictError when organization name already exists', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Bob',
        lastName: 'Johnson',
        email: 'bob@example.com',
        organizationName: 'Existing Organization',
        password: 'BobPass123!',
      };

      // Mock that email doesn't exist
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock that organization name already exists
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue({
        id: 'existing-org-id',
        name: signupData.organizationName,
      });

      // Act & Assert
      await expect(signupService.signup(signupData)).rejects.toThrow(
        'Organization name already taken',
      );

      // Verify that we checked for existing email
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: signupData.email },
      });

      // Verify that we checked for existing organization
      expect(prisma.organization.findUnique).toHaveBeenCalledWith({
        where: { name: signupData.organizationName },
      });

      // Verify that we didn't proceed to create anything
      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(generateOrganizationSlug).not.toHaveBeenCalled();
      expect(hashPassword).not.toHaveBeenCalled();
      expect(generateVerificationToken).not.toHaveBeenCalled();
      expect(sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('should throw NotFoundError when owner role is missing', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Alice',
        lastName: 'Williams',
        email: 'alice@example.com',
        organizationName: 'Alice Organization',
        password: 'AlicePass123!',
      };

      const mockUserId = 'user-456';
      const mockOrgId = 'org-456';
      const mockPasswordHash = 'hashed-password-456';
      const mockOrgSlug = 'alice-organization';
      const mockVerificationToken = 'verification-token-456';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (generateOrganizationSlug as jest.Mock).mockResolvedValue(mockOrgSlug);
      (hashPassword as jest.Mock).mockResolvedValue(mockPasswordHash);
      (generateVerificationToken as jest.Mock).mockReturnValue(mockVerificationToken);

      // Mock transaction with owner role not found
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: mockUserId,
              email: signupData.email,
              passwordHash: mockPasswordHash,
              status: 'PENDING',
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({
              id: 'profile-456',
              userId: mockUserId,
              firstName: signupData.firstName,
              lastName: signupData.lastName,
            }),
          },
          organization: {
            create: jest.fn().mockResolvedValue({
              id: mockOrgId,
              name: signupData.organizationName,
              slug: mockOrgSlug,
            }),
          },
          role: {
            findFirst: jest.fn().mockResolvedValue(null), // Owner role not found
          },
        };

        return callback(mockTx);
      });

      (prisma.$transaction as jest.Mock).mockImplementation(mockTransaction);

      // Act & Assert
      await expect(signupService.signup(signupData)).rejects.toThrow(
        'Owner role not found. Please run database seed.',
      );

      // Verify pre-checks were called
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: signupData.email },
      });
      expect(prisma.organization.findUnique).toHaveBeenCalledWith({
        where: { name: signupData.organizationName },
      });

      // Verify transaction was attempted
      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify email was NOT sent (transaction failed)
      expect(sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('should hash password correctly', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Test',
        lastName: 'User',
        email: 'hashtest@example.com',
        organizationName: 'Hash Test Org',
        password: 'PlainTextPassword123!',
      };

      const expectedHashedPassword = 'bcrypt$hashed$password$123';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock password hashing
      (hashPassword as jest.Mock).mockResolvedValue(expectedHashedPassword);

      // Mock other utilities
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('hash-test-org');
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');

      // Mock successful transaction
      const mockTransaction = jest.fn().mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockImplementation((data) => {
              // Verify the hashed password is being stored, not the plain text
              expect(data.data.passwordHash).toBe(expectedHashedPassword);
              expect(data.data.passwordHash).not.toBe(signupData.password);

              return Promise.resolve({
                id: 'user-hash-test',
                email: signupData.email,
                passwordHash: data.data.passwordHash,
                status: 'PENDING',
              });
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
          },
          organization: {
            create: jest.fn().mockResolvedValue({
              id: 'org-hash-test',
              name: signupData.organizationName,
              slug: 'hash-test-org',
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
      await signupService.signup(signupData);

      // Assert
      expect(hashPassword).toHaveBeenCalledWith(signupData.password);
      expect(hashPassword).toHaveBeenCalledTimes(1);

      // Verify password was hashed before being passed to transaction
      expect(addPasswordToHistory).toHaveBeenCalledWith(
        'user-hash-test',
        expectedHashedPassword,
        expect.anything(),
      );
    });
  });
});
