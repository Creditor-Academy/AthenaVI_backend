const prisma = require('../../shared/config/prismaClient');

const getWorkspaceCredits = async (workspaceId) => {
  return prisma.workspace.findUnique({
    where: { id: workspaceId },
    select: {
      id: true,
      credits: true,
      type: true,
      ownerId: true,
      name: true,
    },
  });
};

const getUserCredits = async (userId) => {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      credits: true,
      email: true,
      name: true,
      isPlatformSuperadmin: true,
    },
  });
};

const findTransactionByIdempotencyKey = async (idempotencyKey) => {
  if (!idempotencyKey) return null;
  return prisma.creditTransaction.findUnique({
    where: { idempotencyKey },
  });
};

const createCreditTransaction = async (tx, data) => {
  return tx.creditTransaction.create({ data });
};

const incrementUserCredits = async (tx, userId, delta) => {
  return tx.user.update({
    where: { id: userId },
    data: { credits: { increment: delta } },
    select: { id: true, credits: true },
  });
};

const incrementWorkspaceCredits = async (tx, workspaceId, delta) => {
  return tx.workspace.update({
    where: { id: workspaceId },
    data: { credits: { increment: delta } },
    select: { id: true, credits: true },
  });
};

const getWorkspaceCreditHistory = async (workspaceId, page, limit, filters = {}) => {
  const skip = (page - 1) * limit;
  const where = {
    workspaceId,
    scope: filters.scope || 'workspace',
    ...(filters.userId ? { userId: filters.userId } : {}),
    ...(filters.types?.length ? { type: { in: filters.types } } : {}),
  };

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({ where }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const getUserScopedCreditHistory = async (userId, page, limit) => {
  const skip = (page - 1) * limit;
  const where = {
    userId,
    scope: 'user',
  };

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({ where }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const getUserCreditHistory = async (workspaceId, userId, page, limit) => {
  const skip = (page - 1) * limit;
  const where = {
    workspaceId,
    userId,
    scope: 'workspace',
  };

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({ where }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const getAllUserCreditHistory = async (userId, page, limit, typeFilter) => {
  const skip = (page - 1) * limit;
  const where = {
    userId,
    ...(typeFilter ? { type: typeFilter } : {}),
  };

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({ where }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const listUsersWithCredits = async ({ page, limit, search }) => {
  const skip = (page - 1) * limit;
  const where = search
    ? {
        email: { contains: search, mode: 'insensitive' },
      }
    : {};

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        name: true,
        credits: true,
        isPlatformSuperadmin: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.user.count({ where }),
  ]);

  return {
    users,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const aggregateUsageReport = async ({ from, to, workspaceId, userId }) => {
  const where = {
    type: 'usage',
    createdAt: {},
  };
  if (from) where.createdAt.gte = new Date(from);
  if (to) where.createdAt.lte = new Date(to);
  if (workspaceId) where.workspaceId = workspaceId;
  if (userId) where.userId = userId;

  const rows = await prisma.creditTransaction.findMany({
    where,
    select: {
      amount: true,
      metadata: true,
      scope: true,
      workspaceId: true,
      userId: true,
    },
  });

  let totalUsageAc = 0;
  let estimatedHeygenUsd = 0;
  for (const row of rows) {
    totalUsageAc += Math.abs(row.amount);
    const meta = row.metadata;
    if (meta && typeof meta === 'object' && meta.heygenUsdCost != null) {
      estimatedHeygenUsd += Number(meta.heygenUsdCost) || 0;
    }
  }

  return {
    transactionCount: rows.length,
    totalUsageAc,
    estimatedHeygenUsd,
  };
};

const usageByMemberInWorkspace = async (workspaceId, page, limit) => {
  const rows = await prisma.creditTransaction.groupBy({
    by: ['userId'],
    where: {
      workspaceId,
      scope: 'workspace',
      type: 'usage',
    },
    _sum: { amount: true },
    _count: { id: true },
  });

  const userIds = rows.map((r) => r.userId);
  const users = await prisma.user.findMany({
    where: { id: { in: userIds } },
    select: { id: true, email: true, name: true },
  });
  const userMap = new Map(users.map((u) => [u.id, u]));

  const allMembers = rows
    .map((r) => ({
      userId: r.userId,
      user: userMap.get(r.userId) || null,
      totalUsageAc: Math.abs(r._sum.amount || 0),
      transactionCount: r._count.id,
    }))
    .sort((a, b) => b.totalUsageAc - a.totalUsageAc);

  const total = allMembers.length;
  const skip = (page - 1) * limit;
  const members = allMembers.slice(skip, skip + limit);

  return {
    members,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

module.exports = {
  getWorkspaceCredits,
  getUserCredits,
  findTransactionByIdempotencyKey,
  createCreditTransaction,
  incrementUserCredits,
  incrementWorkspaceCredits,
  getWorkspaceCreditHistory,
  getUserScopedCreditHistory,
  getUserCreditHistory,
  getAllUserCreditHistory,
  listUsersWithCredits,
  aggregateUsageReport,
  usageByMemberInWorkspace,
  prisma,
};
