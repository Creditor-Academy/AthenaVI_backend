const prisma = require('../../shared/config/prismaClient');
const {
  hasPlatformSuperadminAccess,
  parseSuperadminEmails,
} = require('../../shared/services/platformSuperadmin.service');

const USER_SUMMARY_SELECT = {
  id: true,
  email: true,
  name: true,
  credits: true,
  storageLimit: true,
  storageUsed: true,
  isPlatformSuperadmin: true,
  pausedAt: true,
  pauseReason: true,
  createdAt: true,
};

const findUserLifecycleState = async (userId) =>
  prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, isPlatformSuperadmin: true, pausedAt: true },
  });

const setUserPaused = async (userId, { pausedAt, pauseReason }) =>
  prisma.user.update({
    where: { id: userId },
    data: { pausedAt, pauseReason },
    select: USER_SUMMARY_SELECT,
  });

/** TEAM workspaces the user owns that still have other members (deleting the owner would wipe them). */
const findOwnedSharedTeamWorkspaces = async (userId) =>
  prisma.workspace.findMany({
    where: {
      ownerId: userId,
      type: 'TEAM',
      members: { some: { userId: { not: userId } } },
    },
    select: { id: true, name: true },
    orderBy: { createdAt: 'asc' },
    take: 20,
  });

const findUserSummaryById = async (userId) =>
  prisma.user.findUnique({ where: { id: userId }, select: USER_SUMMARY_SELECT });

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
  findUserLifecycleState,
  setUserPaused,
  findOwnedSharedTeamWorkspaces,
  findUserSummaryById,
  listWorkspacesWithCredits,
  countAccessibleSuperadminsAfterChange,
  updateUserPlatformAccess,
};
