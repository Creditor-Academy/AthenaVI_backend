const prisma = require('../../shared/config/prismaClient');

const findUserById = (userId) => {
  return prisma.user.findUnique({
    where: { id: userId },
  });
};

const createAsset = (db, data) => {
  console.log(db, data);

  return db.asset.create({ data });
};

const incrementUserStorage = (db, userId, size) => {
  return db.user.update({
    where: { id: userId },
    data: {
      storageUsed: {
        increment: size,
      },
    },
  });
};

const findAssets = ({ workspaceId, userId, isPrivate, take, skip }) => {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);

  return prisma.asset.findMany({
    where: {
      workspaceId,
      ...(isPrivate && { uploadedBy: userId }),
    },
    take: limit,
    skip: offset,
    orderBy: {
      createdAt: 'desc',
    },
  });
};

module.exports = {
  findUserById,
  createAsset,
  incrementUserStorage,
  findAssets,
};
