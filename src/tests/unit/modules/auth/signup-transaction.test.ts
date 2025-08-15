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

describe('SignupService - Signup Transaction Tests', () => {
  let signupService: SignupService;

  beforeEach(() => {
    signupService = new SignupService();
    jest.clearAllMocks();
  });

  describe('signup', () => {
    it('should send verification email', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Email',
        lastName: 'Test',
        email: 'emailtest@example.com',
        organizationName: 'Email Test Org',
        password: 'EmailPass123!',
      };

      const mockVerificationToken = 'email-verification-token-xyz789';

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateVerificationToken as jest.Mock).mockReturnValue(mockVerificationToken);
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('email-test-org');

      // Mock successful transaction
      const mockTx = {
        user: {
          create: jest.fn().mockResolvedValue({
            id: 'user-email-test',
            email: signupData.email,
          }),
        },
        profile: {
          create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
        },
        organization: {
          create: jest.fn().mockResolvedValue({
            id: 'org-email-test',
            name: signupData.organizationName,
            slug: 'email-test-org',
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

      // Mock email sending
      (sendVerificationEmail as jest.Mock).mockResolvedValue(undefined);

      // Act
      await signupService.signup(signupData);

      // Assert
      // Verify email was sent with correct parameters
      expect(sendVerificationEmail).toHaveBeenCalledWith(
        {
          email: signupData.email,
          firstName: signupData.firstName,
        },
        mockVerificationToken,
      );
      expect(sendVerificationEmail).toHaveBeenCalledTimes(1);

      // Verify transaction was called (email is sent after it completes)
      expect(prisma.$transaction).toHaveBeenCalled();
    });

    it('should rollback transaction on any failure', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'Rollback',
        lastName: 'Test',
        email: 'rollback@example.com',
        organizationName: 'Rollback Test Org',
        password: 'RollbackPass123!',
      };

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('rollback-test-org');

      // Mock transaction that fails during organization creation
      const mockError = new Error('Database constraint violation');
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: 'user-rollback-test',
              email: signupData.email,
            }),
          },
          profile: {
            create: jest.fn().mockResolvedValue({ id: 'profile-123' }),
          },
          organization: {
            create: jest.fn().mockRejectedValue(mockError), // Simulate failure
          },
          role: {
            findFirst: jest.fn().mockResolvedValue({ id: 'role-123', name: 'owner' }),
          },
          organizationUser: {
            create: jest.fn(),
          },
          emailVerification: {
            create: jest.fn(),
          },
        };

        // Transaction should throw the error, causing rollback
        return callback(mockTx);
      });

      // Act & Assert
      await expect(signupService.signup(signupData)).rejects.toThrow(
        'Database constraint violation',
      );

      // Verify transaction was attempted
      expect(prisma.$transaction).toHaveBeenCalled();

      // Verify email was NOT sent (transaction failed)
      expect(sendVerificationEmail).not.toHaveBeenCalled();

      // Verify audit logs were NOT called (transaction rolled back)
      expect(auditService.logAction).not.toHaveBeenCalled();

      // Verify password history was NOT added (transaction rolled back)
      expect(addPasswordToHistory).not.toHaveBeenCalled();
    });

    it('should rollback transaction if profile creation fails', async () => {
      // Arrange
      const signupData: SignupInput = {
        firstName: 'ProfileFail',
        lastName: 'Test',
        email: 'profilefail@example.com',
        organizationName: 'Profile Fail Org',
        password: 'ProfileFail123!',
      };

      // Mock pre-checks pass
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);

      // Mock utilities
      (hashPassword as jest.Mock).mockResolvedValue('hashed-pwd');
      (generateVerificationToken as jest.Mock).mockReturnValue('token-123');
      (generateOrganizationSlug as jest.Mock).mockResolvedValue('profile-fail-org');

      // Mock transaction that fails during profile creation
      const mockError = new Error('Profile creation failed');
      (prisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue({
              id: 'user-profile-fail',
              email: signupData.email,
            }),
          },
          profile: {
            create: jest.fn().mockRejectedValue(mockError), // Simulate failure here
          },
          organization: {
            create: jest.fn(),
          },
          role: {
            findFirst: jest.fn(),
          },
          organizationUser: {
            create: jest.fn(),
          },
          emailVerification: {
            create: jest.fn(),
          },
        };

        return callback(mockTx);
      });

      // Act & Assert
      await expect(signupService.signup(signupData)).rejects.toThrow('Profile creation failed');

      // Verify no email was sent
      expect(sendVerificationEmail).not.toHaveBeenCalled();

      // In a real database, the user creation would be rolled back too
      // This is handled by the database transaction, not our code
    });
  });
});
