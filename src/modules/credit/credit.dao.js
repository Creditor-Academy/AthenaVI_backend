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
        OR: [
          { email: { contains: search, mode: 'insensitive' } },
          { name: { contains: search, mode: 'insensitive' } },
        ],
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
        storageLimit: true,
        storageUsed: true,
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

const aggregateUsageReport = async ({ from, to, workspaceId, userId, topLimit = 10 }) => {
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
      createdAt: true,
    },
  });

  const { FEATURE_LABELS } = require('./creditHistory.enrich');

  let totalUsageAc = 0;
  let estimatedHeygenUsd = 0;
  const byFeatureMap = new Map();
  const byDayMap = new Map();
  const userUsageMap = new Map();
  const workspaceUsageMap = new Map();

  for (const row of rows) {
    const usageAc = Math.abs(row.amount);
    totalUsageAc += usageAc;
    const meta = row.metadata;
    if (meta && typeof meta === 'object' && meta.heygenUsdCost != null) {
      estimatedHeygenUsd += Number(meta.heygenUsdCost) || 0;
    }

    const feature =
      meta && typeof meta === 'object' && meta.feature ? String(meta.feature) : 'unknown';
    const featureEntry = byFeatureMap.get(feature) || { totalUsageAc: 0, transactionCount: 0 };
    featureEntry.totalUsageAc += usageAc;
    featureEntry.transactionCount += 1;
    byFeatureMap.set(feature, featureEntry);

    const dayKey = row.createdAt.toISOString().slice(0, 10);
    const dayEntry = byDayMap.get(dayKey) || { totalUsageAc: 0, transactionCount: 0 };
    dayEntry.totalUsageAc += usageAc;
    dayEntry.transactionCount += 1;
    byDayMap.set(dayKey, dayEntry);

    if (row.userId) {
      const userEntry = userUsageMap.get(row.userId) || { totalUsageAc: 0, transactionCount: 0 };
      userEntry.totalUsageAc += usageAc;
      userEntry.transactionCount += 1;
      userUsageMap.set(row.userId, userEntry);
    }

    if (row.workspaceId) {
      const wsEntry = workspaceUsageMap.get(row.workspaceId) || {
        totalUsageAc: 0,
        transactionCount: 0,
      };
      wsEntry.totalUsageAc += usageAc;
      wsEntry.transactionCount += 1;
      workspaceUsageMap.set(row.workspaceId, wsEntry);
    }
  }

  const byFeature = [...byFeatureMap.entries()]
    .map(([feature, stats]) => ({
      feature,
      label: FEATURE_LABELS[feature] || feature,
      totalUsageAc: stats.totalUsageAc,
      transactionCount: stats.transactionCount,
    }))
    .sort((a, b) => b.totalUsageAc - a.totalUsageAc);

  const byDay = [...byDayMap.entries()]
    .map(([date, stats]) => ({
      date,
      totalUsageAc: stats.totalUsageAc,
      transactionCount: stats.transactionCount,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const topUserIds = [...userUsageMap.entries()]
    .sort((a, b) => b[1].totalUsageAc - a[1].totalUsageAc)
    .slice(0, topLimit)
    .map(([id]) => id);
  const topWorkspaceIds = [...workspaceUsageMap.entries()]
    .sort((a, b) => b[1].totalUsageAc - a[1].totalUsageAc)
    .slice(0, topLimit)
    .map(([id]) => id);

  const [topUsersData, topWorkspacesData] = await Promise.all([
    topUserIds.length
      ? prisma.user.findMany({
          where: { id: { in: topUserIds } },
          select: { id: true, email: true, name: true },
        })
      : [],
    topWorkspaceIds.length
      ? prisma.workspace.findMany({
          where: { id: { in: topWorkspaceIds } },
          select: { id: true, name: true },
        })
      : [],
  ]);

  const userDataMap = new Map(topUsersData.map((u) => [u.id, u]));
  const workspaceDataMap = new Map(topWorkspacesData.map((w) => [w.id, w]));

  const topUsers = topUserIds.map((id) => {
    const stats = userUsageMap.get(id);
    const user = userDataMap.get(id);
    return {
      userId: id,
      email: user?.email || null,
      name: user?.name || null,
      totalUsageAc: stats.totalUsageAc,
      transactionCount: stats.transactionCount,
    };
  });

  const topWorkspaces = topWorkspaceIds.map((id) => {
    const stats = workspaceUsageMap.get(id);
    const workspace = workspaceDataMap.get(id);
    return {
      workspaceId: id,
      name: workspace?.name || null,
      totalUsageAc: stats.totalUsageAc,
      transactionCount: stats.transactionCount,
    };
  });

  return {
    transactionCount: rows.length,
    totalUsageAc,
    estimatedHeygenUsd,
    byFeature,
    byDay,
    topUsers,
    topWorkspaces,
  };
};

const listPlatformCreditActions = async ({
  page,
  limit,
  from,
  to,
  type,
  scope,
}) => {
  const skip = (page - 1) * limit;
  const where = {
    type: type ? type : { in: ['platform_grant', 'platform_revoke'] },
  };
  if (from || to) {
    where.createdAt = {};
    if (from) where.createdAt.gte = new Date(from);
    if (to) where.createdAt.lte = new Date(to);
  }
  if (scope) {
    where.scope = scope;
  }

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({ where }),
  ]);

  const userIds = new Set();
  const workspaceIds = new Set();
  for (const tx of transactions) {
    if (tx.userId) userIds.add(tx.userId);
    if (tx.workspaceId) workspaceIds.add(tx.workspaceId);
    const meta = tx.metadata && typeof tx.metadata === 'object' ? tx.metadata : {};
    if (meta.grantedByUserId) userIds.add(meta.grantedByUserId);
    if (meta.revokedByUserId) userIds.add(meta.revokedByUserId);
  }

  const [users, workspaces] = await Promise.all([
    userIds.size
      ? prisma.user.findMany({
          where: { id: { in: [...userIds] } },
          select: { id: true, email: true, name: true },
        })
      : [],
    workspaceIds.size
      ? prisma.workspace.findMany({
          where: { id: { in: [...workspaceIds] } },
          select: { id: true, name: true, type: true },
        })
      : [],
  ]);

  const userMap = new Map(users.map((u) => [u.id, u]));
  const workspaceMap = new Map(workspaces.map((w) => [w.id, w]));

  const enriched = transactions.map((tx) => {
    const meta = tx.metadata && typeof tx.metadata === 'object' ? tx.metadata : {};
    const actorId = meta.grantedByUserId || meta.revokedByUserId || null;
    return {
      ...tx,
      user: tx.userId ? userMap.get(tx.userId) || null : null,
      workspace: tx.workspaceId ? workspaceMap.get(tx.workspaceId) || null : null,
      actor: actorId ? userMap.get(actorId) || null : null,
    };
  });

  return {
    transactions: enriched,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
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
  listPlatformCreditActions,
  usageByMemberInWorkspace,
  prisma,
};
