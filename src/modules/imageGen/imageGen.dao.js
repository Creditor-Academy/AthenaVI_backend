const prisma = require('../../shared/config/prismaClient');

function createGeneration(data) {
  return prisma.imageGeneration.create({ data });
}

function findById(id, workspaceId) {
  return prisma.imageGeneration.findFirst({
    where: { id, workspaceId },
    include: {
      asset: true,
    },
  });
}

function listGenerations({ workspaceId, userId, isPrivate, take, skip }) {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);

  return prisma.imageGeneration.findMany({
    where: {
      workspaceId,
      ...(isPrivate && userId ? { userId } : {}),
    },
    take: limit,
    skip: offset,
    orderBy: { createdAt: 'desc' },
    include: {
      asset: {
        select: {
          id: true,
          name: true,
          url: true,
          type: true,
          source: true,
        },
      },
    },
  });
}

module.exports = {
  createGeneration,
  findById,
  listGenerations,
};
