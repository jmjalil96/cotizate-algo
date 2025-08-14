import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // ==================== PERMISSIONS ====================
  console.log('Creating permissions...');
  
  const permissions = [
    // User Management
    { resource: 'users', action: 'create', description: 'Create new users' },
    { resource: 'users', action: 'read', description: 'View user information' },
    { resource: 'users', action: 'update', description: 'Update user information' },
    { resource: 'users', action: 'delete', description: 'Delete users' },
    
    // Organization Management
    { resource: 'organization', action: 'read', description: 'View organization details' },
    { resource: 'organization', action: 'update', description: 'Update organization settings' },
    { resource: 'organization', action: 'delete', description: 'Delete organization' },
    
    // Role Management
    { resource: 'roles', action: 'create', description: 'Create new roles' },
    { resource: 'roles', action: 'read', description: 'View roles' },
    { resource: 'roles', action: 'update', description: 'Update role permissions' },
    { resource: 'roles', action: 'delete', description: 'Delete roles' },
    
    // Member Management
    { resource: 'members', action: 'invite', description: 'Invite new members' },
    { resource: 'members', action: 'read', description: 'View organization members' },
    { resource: 'members', action: 'update', description: 'Update member roles' },
    { resource: 'members', action: 'remove', description: 'Remove members from organization' },
    
    // Billing
    { resource: 'billing', action: 'read', description: 'View billing information' },
    { resource: 'billing', action: 'manage', description: 'Manage billing and subscriptions' },
    
    // Projects (example resource for future)
    { resource: 'projects', action: 'create', description: 'Create new projects' },
    { resource: 'projects', action: 'read', description: 'View projects' },
    { resource: 'projects', action: 'update', description: 'Update projects' },
    { resource: 'projects', action: 'delete', description: 'Delete projects' },
    
    // Audit Logs
    { resource: 'audit_logs', action: 'read', description: 'View audit logs' },
  ];

  const createdPermissions = await Promise.all(
    permissions.map(permission =>
      prisma.permission.upsert({
        where: {
          resource_action: {
            resource: permission.resource,
            action: permission.action,
          },
        },
        update: {
          description: permission.description,
        },
        create: permission,
      })
    )
  );

  console.log(`✅ Created ${createdPermissions.length} permissions`);

  // ==================== GLOBAL ROLES ====================
  console.log('Creating global roles...');

  // Create global roles (these are templates that get copied for each org)
  const ownerRole = await prisma.role.create({
    data: {
      name: 'owner',
      description: 'Full organization control',
    },
  });

  const adminRole = await prisma.role.create({
    data: {
      name: 'admin',
      description: 'Administrative access',
    },
  });

  const memberRole = await prisma.role.create({
    data: {
      name: 'member',
      description: 'Standard member access',
    },
  });

  const viewerRole = await prisma.role.create({
    data: {
      name: 'viewer',
      description: 'Read-only access',
    },
  });

  console.log('✅ Created global roles');

  // ==================== ROLE PERMISSIONS ====================
  console.log('Assigning permissions to roles...');

  // Owner gets all permissions
  const allPermissions = await prisma.permission.findMany();
  await Promise.all(
    allPermissions.map(permission =>
      prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: ownerRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: ownerRole.id,
          permissionId: permission.id,
        },
      })
    )
  );

  // Admin gets most permissions (exclude org deletion and billing)
  const adminPermissions = await prisma.permission.findMany({
    where: {
      NOT: {
        OR: [
          { resource: 'organization', action: 'delete' },
          { resource: 'billing', action: 'manage' },
        ],
      },
    },
  });

  await Promise.all(
    adminPermissions.map(permission =>
      prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: adminRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: adminRole.id,
          permissionId: permission.id,
        },
      })
    )
  );

  // Member gets basic permissions
  const memberPermissions = await prisma.permission.findMany({
    where: {
      OR: [
        { resource: 'projects', action: { in: ['create', 'read', 'update'] } },
        { resource: 'organization', action: 'read' },
        { resource: 'members', action: 'read' },
        { resource: 'users', action: 'read' },
      ],
    },
  });

  await Promise.all(
    memberPermissions.map(permission =>
      prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: memberRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: memberRole.id,
          permissionId: permission.id,
        },
      })
    )
  );

  // Viewer gets read-only permissions
  const viewerPermissions = await prisma.permission.findMany({
    where: {
      action: 'read',
    },
  });

  await Promise.all(
    viewerPermissions.map(permission =>
      prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: viewerRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: viewerRole.id,
          permissionId: permission.id,
        },
      })
    )
  );

  console.log('✅ Assigned permissions to roles');

  // ==================== SUMMARY ====================
  const totalPermissions = await prisma.permission.count();
  const totalRoles = await prisma.role.count();
  const totalRolePermissions = await prisma.rolePermission.count();

  console.log('\n📊 Seed Summary:');
  console.log(`   - Permissions: ${totalPermissions}`);
  console.log(`   - Roles: ${totalRoles}`);
  console.log(`   - Role-Permission mappings: ${totalRolePermissions}`);
  console.log('\n✨ Database seeded successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });