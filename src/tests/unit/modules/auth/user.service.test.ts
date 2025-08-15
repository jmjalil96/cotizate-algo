import { UserService } from '@/modules/auth/services/user.service';
import { prisma } from '@/core/database/prisma.client';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { logger } from '@/common/utils/logger';

// Mock dependencies
jest.mock('@/core/database/prisma.client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
    },
    profile: {
      update: jest.fn(),
    },
    organizationUser: {
      findMany: jest.fn(),
    },
  },
}));

jest.mock('@/common/utils/logger', () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
  },
}));

describe('UserService', () => {
  let userService: UserService;

  beforeEach(() => {
    userService = new UserService();
    jest.clearAllMocks();
  });

  describe('getCurrentUser', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      emailVerified: true,
      status: 'ACTIVE',
      createdAt: new Date('2024-01-01'),
      lastLoginAt: new Date('2024-01-15'),
      profile: {
        firstName: 'Test',
        lastName: 'User',
        timezone: 'America/New_York',
        avatarUrl: 'https://avatar.com/user.jpg',
        phoneNumber: '+1234567890',
      },
      organizationUsers: [
        {
          organization: {
            id: 'org-123',
            name: 'Test Organization',
            slug: 'test-org',
          },
          role: {
            id: 'role-123',
            name: 'owner',
            description: 'Organization owner',
          },
        },
      ],
    };

    it('should return complete user profile for valid user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getCurrentUser('user-123');

      expect(result).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        emailVerified: mockUser.emailVerified,
        status: mockUser.status,
        profile: {
          firstName: mockUser.profile.firstName,
          lastName: mockUser.profile.lastName,
          timezone: mockUser.profile.timezone,
          avatarUrl: mockUser.profile.avatarUrl,
          phoneNumber: mockUser.profile.phoneNumber,
        },
        organization: {
          id: mockUser.organizationUsers[0].organization.id,
          name: mockUser.organizationUsers[0].organization.name,
          slug: mockUser.organizationUsers[0].organization.slug,
        },
        role: {
          id: mockUser.organizationUsers[0].role.id,
          name: mockUser.organizationUsers[0].role.name,
          description: mockUser.organizationUsers[0].role.description,
        },
        createdAt: mockUser.createdAt,
        lastLoginAt: mockUser.lastLoginAt,
      });

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-123' },
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
    });

    it('should handle user without profile', async () => {
      const userWithoutProfile = {
        ...mockUser,
        profile: null,
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWithoutProfile);

      const result = await userService.getCurrentUser('user-123');

      expect(result.profile).toBeNull();
    });

    it('should throw error for non-existent user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(userService.getCurrentUser('non-existent')).rejects.toThrow(NotFoundError);
      await expect(userService.getCurrentUser('non-existent')).rejects.toThrow('User not found');

      expect(logger.error).toHaveBeenCalledWith(
        { userId: 'non-existent' },
        'User not found for /me endpoint',
      );
    });

    it('should throw error for inactive user', async () => {
      const inactiveUser = { ...mockUser, status: 'SUSPENDED' };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(inactiveUser);

      await expect(userService.getCurrentUser('user-123')).rejects.toThrow(UnauthorizedError);
      await expect(userService.getCurrentUser('user-123')).rejects.toThrow('Account is not active');

      expect(logger.warn).toHaveBeenCalledWith(
        { userId: 'user-123', status: 'SUSPENDED' },
        'Inactive user attempted to access /me endpoint',
      );
    });

    it('should throw error for user without organization', async () => {
      const userWithoutOrg = { ...mockUser, organizationUsers: [] };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWithoutOrg);

      await expect(userService.getCurrentUser('user-123')).rejects.toThrow(NotFoundError);
      await expect(userService.getCurrentUser('user-123')).rejects.toThrow(
        'No organization associated with this account',
      );

      expect(logger.error).toHaveBeenCalledWith(
        { userId: 'user-123' },
        'User has no organization association',
      );
    });
  });

  describe('getUserProfile', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      profile: {
        firstName: 'Test',
        lastName: 'User',
        timezone: 'America/New_York',
        avatarUrl: 'https://avatar.com/user.jpg',
        phoneNumber: '+1234567890',
      },
    };

    it('should return limited profile for another user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getUserProfile('user-123', 'viewer-456');

      expect(result).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        profile: {
          firstName: mockUser.profile.firstName,
          lastName: mockUser.profile.lastName,
          timezone: mockUser.profile.timezone,
          avatarUrl: mockUser.profile.avatarUrl,
          phoneNumber: null, // Phone number hidden from other users
        },
      });

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        include: {
          profile: true,
        },
      });
    });

    it('should handle user without profile', async () => {
      const userWithoutProfile = { ...mockUser, profile: null };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userWithoutProfile);

      const result = await userService.getUserProfile('user-123', 'viewer-456');

      expect(result.profile).toBeNull();
    });

    it('should throw error for non-existent user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(userService.getUserProfile('non-existent', 'viewer-456')).rejects.toThrow(
        NotFoundError,
      );
      await expect(userService.getUserProfile('non-existent', 'viewer-456')).rejects.toThrow(
        'User not found',
      );
    });
  });

  describe('updateProfile', () => {
    const mockUser = {
      id: 'user-123',
      status: 'ACTIVE',
    };

    const updateData = {
      firstName: 'Updated',
      lastName: 'Name',
      timezone: 'Europe/London',
      phoneNumber: '+9876543210',
      avatarUrl: 'https://newavatar.com/user.jpg',
    };

    it('should successfully update user profile', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.profile.update as jest.Mock).mockResolvedValue({});

      await userService.updateProfile('user-123', updateData);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-123' },
      });
      expect(prisma.profile.update).toHaveBeenCalledWith({
        where: { userId: 'user-123' },
        data: updateData,
      });
      expect(logger.info).toHaveBeenCalledWith(
        { userId: 'user-123', updates: Object.keys(updateData) },
        'User profile updated',
      );
    });

    it('should update partial profile data', async () => {
      const partialUpdate = { firstName: 'NewName' };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.profile.update as jest.Mock).mockResolvedValue({});

      await userService.updateProfile('user-123', partialUpdate);

      expect(prisma.profile.update).toHaveBeenCalledWith({
        where: { userId: 'user-123' },
        data: partialUpdate,
      });
    });

    it('should throw error for non-existent user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(userService.updateProfile('non-existent', updateData)).rejects.toThrow(
        NotFoundError,
      );
      await expect(userService.updateProfile('non-existent', updateData)).rejects.toThrow(
        'User not found',
      );

      expect(prisma.profile.update).not.toHaveBeenCalled();
    });

    it('should throw error for inactive user', async () => {
      const inactiveUser = { ...mockUser, status: 'SUSPENDED' };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(inactiveUser);

      await expect(userService.updateProfile('user-123', updateData)).rejects.toThrow(
        UnauthorizedError,
      );
      await expect(userService.updateProfile('user-123', updateData)).rejects.toThrow(
        'Account is not active',
      );

      expect(prisma.profile.update).not.toHaveBeenCalled();
    });
  });

  describe('getUserOrganizations', () => {
    const mockOrganizations = [
      {
        organization: {
          id: 'org-123',
          name: 'Test Org 1',
          slug: 'test-org-1',
        },
        role: {
          id: 'role-123',
          name: 'owner',
          description: 'Organization owner',
        },
        joinedAt: new Date('2024-01-01'),
      },
      {
        organization: {
          id: 'org-456',
          name: 'Test Org 2',
          slug: 'test-org-2',
        },
        role: {
          id: 'role-456',
          name: 'member',
          description: 'Team member',
        },
        joinedAt: new Date('2024-02-01'),
      },
    ];

    it('should return list of user organizations', async () => {
      (prisma.organizationUser.findMany as jest.Mock).mockResolvedValue(mockOrganizations);

      const result = await userService.getUserOrganizations('user-123');

      expect(result).toEqual([
        {
          id: 'org-123',
          name: 'Test Org 1',
          slug: 'test-org-1',
          role: {
            id: 'role-123',
            name: 'owner',
            description: 'Organization owner',
          },
          joinedAt: mockOrganizations[0].joinedAt,
        },
        {
          id: 'org-456',
          name: 'Test Org 2',
          slug: 'test-org-2',
          role: {
            id: 'role-456',
            name: 'member',
            description: 'Team member',
          },
          joinedAt: mockOrganizations[1].joinedAt,
        },
      ]);

      expect(prisma.organizationUser.findMany).toHaveBeenCalledWith({
        where: { userId: 'user-123' },
        include: {
          organization: true,
          role: true,
        },
      });
    });

    it('should return empty array for user with no organizations', async () => {
      (prisma.organizationUser.findMany as jest.Mock).mockResolvedValue([]);

      const result = await userService.getUserOrganizations('user-123');

      expect(result).toEqual([]);
    });
  });
});
