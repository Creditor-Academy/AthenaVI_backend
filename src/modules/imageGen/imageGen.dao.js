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

function findGlobalById(id) {
  return prisma.imageGeneration.findUnique({
    where: { id },
    include: {
      asset: true,
      user: {
        select: {
          name: true,
        },
      },
    },
  });
}

function hasPublicTweak(parentId) {
  return prisma.imageGeneration.findFirst({
    where: {
      parentId,
      action: 'public_tweak'
    }
  }).then(res => !!res);
}

function listGenerations({ workspaceId, userId, isPrivate, take, skip, mode, threadId }) {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);

  return prisma.imageGeneration.findMany({
    where: {
      workspaceId,
      ...(isPrivate && userId ? { userId } : {}),
      ...(mode ? { mode } : {}),
      ...(threadId ? { threadId } : {}),
      deletedAt: null,
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

function setFeedback(id, workspaceId, feedback) {
  return prisma.imageGeneration.updateMany({
    where: { id, workspaceId, deletedAt: null },
    data: { feedback },
  });
}

function hideGenerations(ids, workspaceId) {
  return prisma.imageGeneration.updateMany({
    where: { id: { in: ids }, workspaceId, deletedAt: null },
    data: { deletedAt: new Date() },
  });
}

function setThreadId(id, threadId) {
  return prisma.imageGeneration.update({
    where: { id },
    data: { threadId },
  });
}

module.exports = {
  createGeneration,
  findById,
  findGlobalById,
  hasPublicTweak,
  listGenerations,
  setFeedback,
  hideGenerations,
  setThreadId,
};
