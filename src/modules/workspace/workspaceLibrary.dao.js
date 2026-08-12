const prisma = require('../../shared/config/prismaClient');

async function countByCategory({ workspaceId, userId, isPrivate }) {
  const imageWhere = {
    workspaceId,
    ...(isPrivate && userId ? { userId } : {}),
  };

  const [video, presentation, image] = await Promise.all([
    prisma.project.count({
      where: { workspaceId, type: 'VIDEO' },
    }),
    prisma.project.count({
      where: { workspaceId, type: 'PRESENTATION' },
    }),
    prisma.imageGeneration.count({
      where: imageWhere,
    }),
  ]);

  return { video, presentation, image };
}

module.exports = {
  countByCategory,
};
