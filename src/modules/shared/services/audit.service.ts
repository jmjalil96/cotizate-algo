import { prisma } from '@/core/database/prisma.client';
import { Prisma } from '@prisma/client';

export interface AuditLogEntry {
  userId?: string;
  organizationId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  details?: Record<string, any>;
  ipAddress?: string;
}

export class AuditService {
  async logAction(
    entry: AuditLogEntry,
    tx?: Prisma.TransactionClient
  ): Promise<void> {
    const client = tx || prisma;
    await client.auditLog.create({
      data: {
        userId: entry.userId,
        organizationId: entry.organizationId,
        action: entry.action,
        resource: entry.resource,
        resourceId: entry.resourceId,
        details: entry.details || undefined,
        ipAddress: entry.ipAddress,
      },
    });
  }

  async logUserAction(
    userId: string,
    action: string,
    resource: string,
    resourceId?: string,
    details?: Record<string, any>,
    ipAddress?: string,
    tx?: Prisma.TransactionClient
  ): Promise<void> {
    await this.logAction({
      userId,
      action,
      resource,
      resourceId,
      details,
      ipAddress,
    }, tx);
  }

  async logOrganizationAction(
    organizationId: string,
    action: string,
    resource: string,
    resourceId?: string,
    userId?: string,
    details?: Record<string, any>,
    ipAddress?: string,
    tx?: Prisma.TransactionClient
  ): Promise<void> {
    await this.logAction({
      userId,
      organizationId,
      action,
      resource,
      resourceId,
      details,
      ipAddress,
    }, tx);
  }

  async getAuditLogs(filters: {
    userId?: string;
    organizationId?: string;
    action?: string;
    resource?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }) {
    const where: any = {};

    if (filters.userId) where.userId = filters.userId;
    if (filters.organizationId) where.organizationId = filters.organizationId;
    if (filters.action) where.action = filters.action;
    if (filters.resource) where.resource = filters.resource;

    if (filters.startDate || filters.endDate) {
      where.createdAt = {};
      if (filters.startDate) where.createdAt.gte = filters.startDate;
      if (filters.endDate) where.createdAt.lte = filters.endDate;
    }

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: filters.limit || 50,
        skip: filters.offset || 0,
        include: {
          user: {
            select: {
              id: true,
              email: true,
            },
          },
        },
      }),
      prisma.auditLog.count({ where }),
    ]);

    return {
      logs,
      total,
      limit: filters.limit || 50,
      offset: filters.offset || 0,
    };
  }
}

export const auditService = new AuditService();