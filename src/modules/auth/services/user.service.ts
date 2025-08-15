import { prisma } from '@/core/database/prisma.client';
import { NotFoundError, UnauthorizedError } from '@/common/exceptions/app.error';
import { logger } from '@/common/utils/logger';

export interface UserProfileData {
  id: string;
  email: string;
  emailVerified: boolean;
  status: string;
  profile: {
    firstName: string;
    lastName: string;
    timezone: string;
    avatarUrl: string | null;
    phoneNumber: string | null;
  } | null;
  organization: {
    id: string;
    name: string;
    slug: string;
  };
  role: {
    id: string;
    name: string;
    description: string | null;
  };
  createdAt: Date;
  lastLoginAt: Date | null;
}

export class UserService {
  /**
   * Get current authenticated user's full profile
   * Returns comprehensive user data including organization and role
   */
  async getCurrentUser(userId: string): Promise<UserProfileData> {
    // Fetch user with all necessary relations
    const user = await prisma.user.findUnique({
      where: { id: userId },
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

    // Check if user exists
    if (!user) {
      logger.error({ userId }, 'User not found for /me endpoint');
      throw new NotFoundError('User not found');
    }

    // Check if user is active
    if (user.status !== 'ACTIVE') {
      logger.warn(
        { userId, status: user.status },
        'Inactive user attempted to access /me endpoint',
      );
      throw new UnauthorizedError('Account is not active');
    }

    // Get the user's first organization (for now, we support single org per user)
    const organizationUser = user.organizationUsers[0];
    if (!organizationUser) {
      logger.error({ userId }, 'User has no organization association');
      throw new NotFoundError('No organization associated with this account');
    }

    // Format and return user data
    return {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
      status: user.status,
      profile: user.profile
        ? {
            firstName: user.profile.firstName,
            lastName: user.profile.lastName,
            timezone: user.profile.timezone,
            avatarUrl: user.profile.avatarUrl,
            phoneNumber: user.profile.phoneNumber,
          }
        : null,
      organization: {
        id: organizationUser.organization.id,
        name: organizationUser.organization.name,
        slug: organizationUser.organization.slug,
      },
      role: {
        id: organizationUser.role.id,
        name: organizationUser.role.name,
        description: organizationUser.role.description,
      },
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
    };
  }

  /**
   * Get user profile by ID
   * For future use - viewing other users' profiles with proper permissions
   */
  async getUserProfile(userId: string, viewerId: string): Promise<Partial<UserProfileData>> {
    // TODO: Add permission checks to ensure viewerId can view userId's profile
    // This will be used for viewing team members' profiles, etc.

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        profile: true,
      },
    });

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Return limited profile data for other users
    return {
      id: user.id,
      email: user.email,
      profile: user.profile
        ? {
            firstName: user.profile.firstName,
            lastName: user.profile.lastName,
            timezone: user.profile.timezone,
            avatarUrl: user.profile.avatarUrl,
            phoneNumber: null, // Don't expose phone number to other users
          }
        : null,
    };
  }

  /**
   * Update user profile
   * For future use - updating profile information
   */
  async updateProfile(
    userId: string,
    data: {
      firstName?: string;
      lastName?: string;
      timezone?: string;
      phoneNumber?: string;
      avatarUrl?: string;
    },
  ): Promise<void> {
    // Check if user exists and is active
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundError('User not found');
    }

    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedError('Account is not active');
    }

    // Update profile
    await prisma.profile.update({
      where: { userId },
      data,
    });

    logger.info({ userId, updates: Object.keys(data) }, 'User profile updated');
  }

  /**
   * Get user's organizations
   * For future use - when supporting multiple organizations per user
   */
  async getUserOrganizations(userId: string) {
    const organizations = await prisma.organizationUser.findMany({
      where: { userId },
      include: {
        organization: true,
        role: true,
      },
    });

    return organizations.map((org) => ({
      id: org.organization.id,
      name: org.organization.name,
      slug: org.organization.slug,
      role: {
        id: org.role.id,
        name: org.role.name,
        description: org.role.description,
      },
      joinedAt: org.joinedAt,
    }));
  }
}

export const userService = new UserService();
