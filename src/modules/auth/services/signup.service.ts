import { prisma } from '@/core/database/prisma.client';
import { ConflictError, NotFoundError } from '@/common/exceptions/app.error';
import { hashPassword, addPasswordToHistory } from '../utils/password.utils';
import { generateVerificationToken } from '../utils/token.utils';
import { generateOrganizationSlug } from '@/modules/shared/utils/slug.utils';
import { sendVerificationEmail } from '@/modules/shared/utils/email.utils';
import { auditService } from '@/modules/shared/services/audit.service';
import type { SignupInput } from '../validators/auth.schema';

export class SignupService {
  /**
   * Handle user registration with organization creation
   * Creates user, profile, organization, and assigns owner role
   */
  async signup(data: SignupInput, ipAddress?: string) {
    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: data.email },
    });

    if (existingUser) {
      throw new ConflictError('Email already registered');
    }

    // Check if organization name already exists
    const existingOrgByName = await prisma.organization.findUnique({
      where: { name: data.organizationName },
    });

    if (existingOrgByName) {
      throw new ConflictError('Organization name already taken');
    }

    // Generate organization slug
    const organizationSlug = await generateOrganizationSlug(data.organizationName);

    // Hash password
    const passwordHash = await hashPassword(data.password);

    // Generate verification token
    const verificationToken = generateVerificationToken();

    // Create everything in a transaction
    const result = await prisma.$transaction(async (tx) => {
      // Create user
      const user = await tx.user.create({
        data: {
          email: data.email,
          passwordHash,
          status: 'PENDING',
        },
      });

      // Create profile
      await tx.profile.create({
        data: {
          userId: user.id,
          firstName: data.firstName,
          lastName: data.lastName,
        },
      });

      // Create organization
      const organization = await tx.organization.create({
        data: {
          name: data.organizationName,
          slug: organizationSlug,
        },
      });

      // Find the global owner role
      const ownerRole = await tx.role.findFirst({
        where: {
          name: 'owner',
          organizationId: null, // Global role
        },
      });

      if (!ownerRole) {
        throw new NotFoundError('Owner role not found. Please run database seed.');
      }

      // Create organization user with owner role
      await tx.organizationUser.create({
        data: {
          userId: user.id,
          organizationId: organization.id,
          roleId: ownerRole.id,
        },
      });

      // Create email verification record
      await tx.emailVerification.create({
        data: {
          userId: user.id,
          email: data.email,
          token: verificationToken,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        },
      });

      // Add password to history
      await addPasswordToHistory(user.id, passwordHash, tx);

      // Create audit log for user signup
      await auditService.logAction(
        {
          userId: user.id,
          action: 'user.signup',
          resource: 'user',
          resourceId: user.id,
          details: {
            email: data.email,
            firstName: data.firstName,
            lastName: data.lastName,
          },
          ipAddress,
        },
        tx,
      );

      // Create audit log for organization creation
      await auditService.logAction(
        {
          userId: user.id,
          organizationId: organization.id,
          action: 'organization.create',
          resource: 'organization',
          resourceId: organization.id,
          details: {
            name: data.organizationName,
            slug: organizationSlug,
          },
          ipAddress,
        },
        tx,
      );

      return {
        user,
        organization,
      };
    });

    // Send verification email (outside transaction)
    await sendVerificationEmail(
      {
        email: data.email,
        firstName: data.firstName,
      },
      verificationToken,
    );

    return {
      message: 'Account created successfully. Please check your email to verify your account.',
      user: {
        id: result.user.id,
        email: result.user.email,
      },
      organization: {
        id: result.organization.id,
        name: result.organization.name,
        slug: result.organization.slug,
      },
    };
  }
}

export const signupService = new SignupService();
