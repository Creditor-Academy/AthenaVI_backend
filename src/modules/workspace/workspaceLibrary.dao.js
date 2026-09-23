const prisma = require('../../shared/config/prismaClient');

async function countByCategory({
  workspaceId,
  userId,
  isPrivate,
  folderId,
  assignmentWhere = {},
}) {
  const imageWhere = {
    workspaceId,
    ...(folderId ? { folderId } : {}),
    ...(isPrivate && userId ? { userId } : {}),
  };

  const projectWhere = {
    workspaceId,
    ...(folderId ? { folderId } : {}),
    ...assignmentWhere,
  };

  const [video, presentation, canvas, image] = await Promise.all([
    prisma.project.count({
      where: { ...projectWhere, type: 'VIDEO' },
    }),
    prisma.project.count({
      where: { ...projectWhere, type: 'PRESENTATION' },
    }),
    prisma.project.count({
      where: { ...projectWhere, type: 'CANVAS' },
    }),
    prisma.imageGenThread.count({
      where: imageWhere,
    }),
  ]);

  return { video, presentation, canvas, image };
}

module.exports = {
  countByCategory,
};
