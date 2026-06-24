const prisma = require('../../shared/config/prismaClient');
const { toBigInt, sumPrismaAggregate } = require('../../shared/utils/byteSize');

const getUserStorage = (userId) => {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      storageLimit: true,
      storageUsed: true,
    },
  });
};

const updateUserStorageLimit = (db, userId, limitBytes) => {
  return db.user.update({
    where: { id: userId },
    data: {
      storageLimit: toBigInt(limitBytes),
    },
    select: {
      id: true,
      email: true,
      name: true,
      storageLimit: true,
      storageUsed: true,
    },
  });
};

const incrementUserStorageLimit = (db, userId, deltaBytes) => {
  return db.user.update({
    where: { id: userId },
    data: {
      storageLimit: {
        increment: toBigInt(deltaBytes),
      },
    },
    select: {
      id: true,
      email: true,
      name: true,
      storageLimit: true,
      storageUsed: true,
    },
  });
};

const incrementUserStorageUsed = (db, userId, deltaBytes) => {
  return db.user.update({
    where: { id: userId },
    data: {
      storageUsed: {
        increment: toBigInt(deltaBytes),
      },
    },
    select: {
      id: true,
      email: true,
      name: true,
      storageLimit: true,
      storageUsed: true,
    },
  });
};

const createStorageTransaction = (db, data) => {
  return db.storageTransaction.create({
    data,
  });
};

const listStorageTransactionsByUser = async (userId, page, limit, type) => {
  const skip = (page - 1) * limit;
  const where = {
    userId,
    ...(type ? { type } : {}),
  };

  const [transactions, total] = await Promise.all([
    prisma.storageTransaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.storageTransaction.count({ where }),
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

const getWorkspaceOwnerStorage = async (workspaceId) => {
  return prisma.workspace.findUnique({
    where: { id: workspaceId },
    select: {
      id: true,
      ownerId: true,
      type: true,
      owner: {
        select: {
          id: true,
          email: true,
          name: true,
          storageLimit: true,
          storageUsed: true,
        },
      },
    },
  });
};

const sumWorkspaceStorageFootprint = async (workspaceId) => {
  const [asset, heygen, renders] = await Promise.all([
    prisma.asset.aggregate({
      where: { workspaceId },
      _sum: { size: true },
    }),
    prisma.heygenResponse.aggregate({
      where: {
        workspaceId,
        s3Key: { not: null },
      },
      _sum: { fileSizeBytes: true },
    }),
    prisma.projectRender.aggregate({
      where: {
        workspaceId,
        status: 'completed',
        s3Key: { not: null },
      },
      _sum: { fileSizeBytes: true },
    }),
  ]);

  return {
    assetBytes: sumPrismaAggregate(asset._sum.size),
    heygenBytes: sumPrismaAggregate(heygen._sum.fileSizeBytes),
    renderBytes: sumPrismaAggregate(renders._sum.fileSizeBytes),
  };
};

const sumOwnerBillableStorageUsed = async (ownerId) => {
  const owned = await prisma.workspace.findMany({
    where: { ownerId },
    select: { id: true },
  });
  const workspaceIds = owned.map((item) => item.id);
  if (!workspaceIds.length) return 0;

  const [asset, heygen, renders] = await Promise.all([
    prisma.asset.aggregate({
      where: { workspaceId: { in: workspaceIds } },
      _sum: { size: true },
    }),
    prisma.heygenResponse.aggregate({
      where: {
        workspaceId: { in: workspaceIds },
        s3Key: { not: null },
      },
      _sum: { fileSizeBytes: true },
    }),
    prisma.projectRender.aggregate({
      where: {
        workspaceId: { in: workspaceIds },
        status: 'completed',
        s3Key: { not: null },
      },
      _sum: { fileSizeBytes: true },
    }),
  ]);

  return (
    sumPrismaAggregate(asset._sum.size) +
    sumPrismaAggregate(heygen._sum.fileSizeBytes) +
    sumPrismaAggregate(renders._sum.fileSizeBytes)
  );
};

const createStorageUpgradeRequest = (data) => {
  return prisma.storageUpgradeRequest.create({ data });
};

const listStorageUpgradeRequestsByUser = async (userId, page, limit, status) => {
  const skip = (page - 1) * limit;
  const where = {
    userId,
    ...(status ? { status } : {}),
  };

  const [requests, total] = await Promise.all([
    prisma.storageUpgradeRequest.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.storageUpgradeRequest.count({ where }),
  ]);

  return {
    requests,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const findLatestPendingStorageUpgradeRequest = (userId) => {
  return prisma.storageUpgradeRequest.findFirst({
    where: {
      userId,
      status: 'PENDING',
    },
    orderBy: { createdAt: 'desc' },
  });
};

const approveLatestPendingStorageUpgradeRequest = async (userId, reviewedByUserId, reviewNote) => {
  const pending = await findLatestPendingStorageUpgradeRequest(userId);
  if (!pending) {
    return null;
  }

  return prisma.storageUpgradeRequest.update({
    where: { id: pending.id },
    data: {
      status: 'APPROVED',
      reviewedAt: new Date(),
      reviewedByUserId,
      reviewNote: reviewNote || null,
    },
  });
};

const listStorageUpgradeRequests = async ({ page, limit, status }) => {
  const skip = (page - 1) * limit;
  const where = status ? { status } : {};

  const [requests, total] = await Promise.all([
    prisma.storageUpgradeRequest.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
      include: {
        user: {
          select: { id: true, email: true, name: true },
        },
      },
    }),
    prisma.storageUpgradeRequest.count({ where }),
  ]);

  return {
    requests,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const findStorageUpgradeRequestById = (requestId) => {
  return prisma.storageUpgradeRequest.findUnique({
    where: { id: requestId },
    include: {
      user: {
        select: { id: true, email: true, name: true },
      },
    },
  });
};

const rejectStorageUpgradeRequest = async ({ requestId, reviewedByUserId, reviewNote }) => {
  const existing = await prisma.storageUpgradeRequest.findUnique({
    where: { id: requestId },
  });
  if (!existing) {
    return null;
  }
  if (existing.status !== 'PENDING') {
    return { error: 'not_pending', request: existing };
  }

  const request = await prisma.storageUpgradeRequest.update({
    where: { id: requestId },
    data: {
      status: 'REJECTED',
      reviewedAt: new Date(),
      reviewedByUserId,
      reviewNote: reviewNote || null,
    },
    include: {
      user: {
        select: { id: true, email: true, name: true },
      },
    },
  });

  return { request };
};

module.exports = {
  getUserStorage,
  updateUserStorageLimit,
  incrementUserStorageLimit,
  incrementUserStorageUsed,
  createStorageTransaction,
  listStorageTransactionsByUser,
  getWorkspaceOwnerStorage,
  sumWorkspaceStorageFootprint,
  sumOwnerBillableStorageUsed,
  createStorageUpgradeRequest,
  listStorageUpgradeRequestsByUser,
  findLatestPendingStorageUpgradeRequest,
  approveLatestPendingStorageUpgradeRequest,
  listStorageUpgradeRequests,
  findStorageUpgradeRequestById,
  rejectStorageUpgradeRequest,
  prisma,
};
