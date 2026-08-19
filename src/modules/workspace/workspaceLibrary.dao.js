const prisma = require('../../shared/config/prismaClient');

async function countByCategory({ workspaceId, userId, isPrivate, folderId }) {
  const imageWhere = {
    workspaceId,
    ...(folderId ? { folderId } : {}),
    ...(isPrivate && userId ? { userId } : {}),
  };

  const projectWhere = {
    workspaceId,
    ...(folderId ? { folderId } : {}),
  };

  const [video, presentation, image] = await Promise.all([
    prisma.project.count({
      where: { ...projectWhere, type: 'VIDEO' },
    }),
    prisma.project.count({
      where: { ...projectWhere, type: 'PRESENTATION' },
    }),
    prisma.imageGenThread.count({
      where: imageWhere,
    }),
  ]);

  return { video, presentation, image };
}

module.exports = {
  countByCategory,
};
