const prisma = require('../../shared/config/prismaClient');

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
      storageLimit: limitBytes,
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
        increment: deltaBytes,
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
        increment: deltaBytes,
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
    assetBytes: asset._sum.size || 0,
    heygenBytes: heygen._sum.fileSizeBytes || 0,
    renderBytes: renders._sum.fileSizeBytes || 0,
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

  return (asset._sum.size || 0) + (heygen._sum.fileSizeBytes || 0) + (renders._sum.fileSizeBytes || 0);
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
  prisma,
};
