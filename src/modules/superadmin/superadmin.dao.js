const prisma = require('../../shared/config/prismaClient');
const {
  hasPlatformSuperadminAccess,
  parseSuperadminEmails,
} = require('../../shared/services/platformSuperadmin.service');

const listWorkspacesWithCredits = async ({ page, limit, search }) => {
  const skip = (page - 1) * limit;
  const where = {
    type: 'TEAM',
    ...(search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' } },
            { owner: { email: { contains: search, mode: 'insensitive' } } },
          ],
        }
      : {}),
  };

  const [workspaces, total] = await Promise.all([
    prisma.workspace.findMany({
      where,
      select: {
        id: true,
        name: true,
        type: true,
        credits: true,
        createdAt: true,
        owner: {
          select: { id: true, email: true, name: true },
        },
        _count: {
          select: { members: true },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.workspace.count({ where }),
  ]);

  return {
    workspaces: workspaces.map((workspace) => ({
      workspaceId: workspace.id,
      name: workspace.name,
      type: workspace.type,
      workspaceCredits: workspace.credits,
      owner: workspace.owner,
      memberCount: workspace._count.members,
      createdAt: workspace.createdAt,
    })),
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

async function countAccessibleSuperadminsAfterChange(targetUserId, nextIsPlatformSuperadmin) {
  const allowlist = parseSuperadminEmails();
  const users = await prisma.user.findMany({
    select: { id: true, email: true, isPlatformSuperadmin: true },
  });

  return users.filter((user) => {
    const effectiveUser =
      user.id === targetUserId
        ? { ...user, isPlatformSuperadmin: nextIsPlatformSuperadmin }
        : user;
    return hasPlatformSuperadminAccess(effectiveUser);
  }).length;
}

const updateUserPlatformAccess = async (userId, isPlatformSuperadmin) => {
  return prisma.user.update({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      isPlatformSuperadmin: true,
    },
    data: { isPlatformSuperadmin },
  });
};

module.exports = {
  listWorkspacesWithCredits,
  countAccessibleSuperadminsAfterChange,
  updateUserPlatformAccess,
};
