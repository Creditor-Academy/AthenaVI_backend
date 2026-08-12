const prisma = require('../../shared/config/prismaClient');

function createContext(data) {
  return prisma.imageGenContext.create({ data });
}

function createContextWithFiles({ context, files }) {
  return prisma.$transaction(async (tx) => {
    const row = await tx.imageGenContext.create({ data: context });
    if (Array.isArray(files) && files.length) {
      await tx.imageGenContextFile.createMany({
        data: files.map((file) => ({
          ...file,
          contextId: row.id,
        })),
      });
    }
    return tx.imageGenContext.findUnique({
      where: { id: row.id },
      include: { files: true },
    });
  });
}

function findById(id, workspaceId, { userId = null, isPrivate = false } = {}) {
  return prisma.imageGenContext.findFirst({
    where: {
      id,
      workspaceId,
      ...(isPrivate && userId ? { userId } : {}),
    },
    include: { files: true },
  });
}

function pinContext(id) {
  return prisma.imageGenContext.updateMany({
    where: { id, pinnedAt: null },
    data: { pinnedAt: new Date() },
  });
}

function deleteContext(id) {
  return prisma.imageGenContext.delete({ where: { id } });
}

function listExpiredUnpinned({ take = 50 } = {}) {
  return prisma.imageGenContext.findMany({
    where: {
      expiresAt: { lt: new Date() },
      pinnedAt: null,
    },
    take: Math.min(Math.max(Number(take) || 50, 1), 200),
    include: { files: true },
    orderBy: { expiresAt: 'asc' },
  });
}

module.exports = {
  createContext,
  createContextWithFiles,
  findById,
  pinContext,
  deleteContext,
  listExpiredUnpinned,
};
