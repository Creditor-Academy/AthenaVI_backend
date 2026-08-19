const prisma = require('../../shared/config/prismaClient');

const headAssetInclude = {
  headGeneration: {
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
  },
};

const threadListInclude = {
  ...headAssetInclude,
  _count: {
    select: {
      messages: true,
      generations: true,
    },
  },
};

function createThread(data) {
  return prisma.imageGenThread.create({ data });
}

function findById(id, workspaceId, { userId = null, isPrivate = false } = {}) {
  return prisma.imageGenThread.findFirst({
    where: {
      id,
      workspaceId,
      ...(isPrivate && userId ? { userId } : {}),
    },
    include: {
      ...headAssetInclude,
      messages: {
        orderBy: { createdAt: 'asc' },
        include: {
          generation: {
            select: {
              id: true,
              url: true,
              s3Key: true,
              action: true,
              creditsCharged: true,
              createdAt: true,
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
          },
        },
      },
      _count: {
        select: {
          messages: true,
          generations: true,
        },
      },
    },
  });
}

function findByRootGenerationId(rootGenerationId, workspaceId) {
  return prisma.imageGenThread.findFirst({
    where: { rootGenerationId, workspaceId },
  });
}

function listThreads({ workspaceId, userId, isPrivate, folderId, take, skip }) {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);

  return prisma.imageGenThread.findMany({
    where: {
      workspaceId,
      ...(folderId ? { folderId } : {}),
      ...(isPrivate && userId ? { userId } : {}),
    },
    take: limit,
    skip: offset,
    orderBy: { updatedAt: 'desc' },
    include: threadListInclude,
  });
}

function countThreads({ workspaceId, userId, isPrivate, folderId }) {
  return prisma.imageGenThread.count({
    where: {
      workspaceId,
      ...(folderId ? { folderId } : {}),
      ...(isPrivate && userId ? { userId } : {}),
    },
  });
}

function updateThread(id, data) {
  return prisma.imageGenThread.update({
    where: { id },
    data,
    include: threadListInclude,
  });
}

function deleteThread(id) {
  return prisma.imageGenThread.delete({ where: { id } });
}

function unlinkGenerations(threadId) {
  return prisma.imageGeneration.updateMany({
    where: { threadId },
    data: { threadId: null },
  });
}

function getFolderThreadStatsByWorkspace(workspaceId) {
  return prisma.imageGenThread.groupBy({
    by: ['folderId'],
    where: { workspaceId },
    _count: { id: true },
    _max: { updatedAt: true },
  });
}

module.exports = {
  createThread,
  findById,
  findByRootGenerationId,
  listThreads,
  countThreads,
  updateThread,
  deleteThread,
  unlinkGenerations,
  getFolderThreadStatsByWorkspace,
  threadListInclude,
};
