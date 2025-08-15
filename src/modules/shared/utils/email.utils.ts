import { env } from '@/core/config/env';
import { logger } from '@/common/utils/logger';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
  from?: string;
}

interface EmailTemplate {
  subject: string;
  html: string;
  text?: string;
}

/**
 * Email queue (in-memory for now, replace with Bull/BullMQ in production)
 */
const emailQueue: EmailOptions[] = [];

/**
 * Create email transporter based on provider
 */
function createTransporter(): Transporter | null {
  const provider = process.env.EMAIL_PROVIDER || 'console';

  if (provider === 'console') {
    return null;
  }

  if (provider === 'inbucket') {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'localhost',
      port: parseInt(process.env.SMTP_PORT || '2500', 10),
      secure: false,
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

  if (provider === 'smtp') {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  logger.warn(`Unknown email provider: ${provider}, falling back to console`);
  return null;
}

/**
 * Render email template
 */
export function renderTemplate(templateName: string, data: Record<string, any>): EmailTemplate {
  const templates: Record<string, (data: any) => EmailTemplate> = {
    verification: renderVerificationEmail,
    passwordReset: renderPasswordResetEmail,
    invitation: renderInvitationEmail,
    welcome: renderWelcomeEmail,
  };

  const renderer = templates[templateName];
  if (!renderer) {
    throw new Error(`Email template "${templateName}" not found`);
  }

  return renderer(data);
}

/**
 * Queue email for sending
 */
export async function queueEmail(options: EmailOptions): Promise<void> {
  emailQueue.push({
    from: options.from || process.env.EMAIL_FROM || 'noreply@example.com',
    ...options,
  });

  // In production, use a proper queue like Bull/BullMQ
  // For now, process immediately
  await processEmailQueue();
}

/**
 * Process email queue
 */
async function processEmailQueue(): Promise<void> {
  const transporter = createTransporter();

  while (emailQueue.length > 0) {
    const email = emailQueue.shift();
    if (email) {
      try {
        if (transporter) {
          // Send via nodemailer
          const info = await transporter.sendMail({
            from: email.from,
            to: email.to,
            subject: email.subject,
            html: email.html,
            text: email.text,
          });

          logger.info(
            {
              to: email.to,
              subject: email.subject,
              messageId: info.messageId,
              provider: process.env.EMAIL_PROVIDER,
            },
            'Email sent successfully',
          );

          if (process.env.EMAIL_PROVIDER === 'inbucket') {
            logger.info('View email at: http://localhost:9000');
          }
        } else {
          // Console fallback
          logger.info(
            {
              to: email.to,
              subject: email.subject,
            },
            'Email (console mode)',
          );

          if (env.NODE_ENV === 'development') {
            logger.debug({ email }, 'Email content');
          }
        }
      } catch (error) {
        logger.error(
          {
            error,
            to: email.to,
            subject: email.subject,
          },
          'Failed to send email',
        );
      }
    }
  }
}

/**
 * Send verification email
 */
export async function sendVerificationEmail(
  user: { email: string; firstName: string },
  token: string,
): Promise<void> {
  const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email?token=${token}`;

  const template = renderVerificationEmail({
    firstName: user.firstName,
    verificationUrl,
  });

  await queueEmail({
    to: user.email,
    ...template,
  });
}

/**
 * Send password reset email
 */
export async function sendPasswordResetEmail(
  user: { email: string; firstName: string },
  token: string,
): Promise<void> {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${token}`;

  const template = renderPasswordResetEmail({
    firstName: user.firstName,
    resetUrl,
  });

  await queueEmail({
    to: user.email,
    ...template,
  });
}

/**
 * Send invitation email
 */
export async function sendInvitationEmail(
  email: string,
  organization: { name: string },
  inviter: { firstName: string; lastName: string },
  token: string,
): Promise<void> {
  const inviteUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/accept-invite?token=${token}`;

  const template = renderInvitationEmail({
    organizationName: organization.name,
    inviterName: `${inviter.firstName} ${inviter.lastName}`,
    inviteUrl,
  });

  await queueEmail({
    to: email,
    ...template,
  });
}

/**
 * Email Templates
 */

function renderVerificationEmail(data: {
  firstName: string;
  verificationUrl: string;
}): EmailTemplate {
  return {
    subject: 'Verify your email address',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { 
              display: inline-block; 
              padding: 12px 24px; 
              background-color: #007bff; 
              color: white; 
              text-decoration: none; 
              border-radius: 4px; 
              margin: 20px 0;
            }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Welcome, ${data.firstName}!</h2>
            <p>Thanks for signing up. Please verify your email address by clicking the button below:</p>
            <a href="${data.verificationUrl}" class="button">Verify Email</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">${data.verificationUrl}</p>
            <p>This link will expire in 24 hours.</p>
            <div class="footer">
              <p>If you didn't create an account, you can safely ignore this email.</p>
            </div>
          </div>
        </body>
      </html>
    `,
    text: `
Welcome, ${data.firstName}!

Thanks for signing up. Please verify your email address by visiting:

${data.verificationUrl}

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.
    `.trim(),
  };
}

function renderPasswordResetEmail(data: { firstName: string; resetUrl: string }): EmailTemplate {
  return {
    subject: 'Reset your password',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { 
              display: inline-block; 
              padding: 12px 24px; 
              background-color: #dc3545; 
              color: white; 
              text-decoration: none; 
              border-radius: 4px; 
              margin: 20px 0;
            }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Hi ${data.firstName},</h2>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <a href="${data.resetUrl}" class="button">Reset Password</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">${data.resetUrl}</p>
            <p>This link will expire in 1 hour.</p>
            <div class="footer">
              <p>If you didn't request a password reset, you can safely ignore this email.</p>
              <p>Your password won't be changed until you create a new one.</p>
            </div>
          </div>
        </body>
      </html>
    `,
    text: `
Hi ${data.firstName},

We received a request to reset your password. Visit the link below to create a new password:

${data.resetUrl}

This link will expire in 1 hour.

If you didn't request a password reset, you can safely ignore this email.
Your password won't be changed until you create a new one.
    `.trim(),
  };
}

function renderInvitationEmail(data: {
  organizationName: string;
  inviterName: string;
  inviteUrl: string;
}): EmailTemplate {
  return {
    subject: `You're invited to join ${data.organizationName}`,
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { 
              display: inline-block; 
              padding: 12px 24px; 
              background-color: #28a745; 
              color: white; 
              text-decoration: none; 
              border-radius: 4px; 
              margin: 20px 0;
            }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>You're invited!</h2>
            <p>${data.inviterName} has invited you to join <strong>${data.organizationName}</strong>.</p>
            <p>Click the button below to accept the invitation and create your account:</p>
            <a href="${data.inviteUrl}" class="button">Accept Invitation</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">${data.inviteUrl}</p>
            <p>This invitation will expire in 7 days.</p>
            <div class="footer">
              <p>If you don't want to join, you can safely ignore this email.</p>
            </div>
          </div>
        </body>
      </html>
    `,
    text: `
You're invited!

${data.inviterName} has invited you to join ${data.organizationName}.

Accept the invitation and create your account:

${data.inviteUrl}

This invitation will expire in 7 days.

If you don't want to join, you can safely ignore this email.
    `.trim(),
  };
}

function renderWelcomeEmail(data: { firstName: string; organizationName: string }): EmailTemplate {
  return {
    subject: `Welcome to ${data.organizationName}!`,
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Welcome aboard, ${data.firstName}!</h2>
            <p>Your account has been successfully created and you're now part of <strong>${data.organizationName}</strong>.</p>
            <p>Here's what you can do next:</p>
            <ul>
              <li>Complete your profile</li>
              <li>Invite team members</li>
              <li>Explore the dashboard</li>
              <li>Configure your settings</li>
            </ul>
            <p>If you have any questions, don't hesitate to reach out to our support team.</p>
            <div class="footer">
              <p>Happy to have you on board!</p>
            </div>
          </div>
        </body>
      </html>
    `,
    text: `
Welcome aboard, ${data.firstName}!

Your account has been successfully created and you're now part of ${data.organizationName}.

Here's what you can do next:
- Complete your profile
- Invite team members
- Explore the dashboard
- Configure your settings

If you have any questions, don't hesitate to reach out to our support team.

Happy to have you on board!
    `.trim(),
  };
}
