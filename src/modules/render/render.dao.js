const prisma = require('../../shared/config/prismaClient');

const createProjectRender = (data) => {
  return prisma.projectRender.create({ data });
};

const updateProjectRender = (id, data) => {
  return prisma.projectRender.update({
    where: { id },
    data,
  });
};

const listProjectRenders = (workspaceId, projectId) => {
  return prisma.projectRender.findMany({
    where: { workspaceId, projectId },
    orderBy: { createdAt: 'desc' },
  });
};

const findProjectRenderById = (workspaceId, projectId, renderId) => {
  return prisma.projectRender.findFirst({
    where: {
      id: renderId,
      workspaceId,
      projectId,
    },
  });
};

const findSceneRenderCache = (projectId, sceneId, sceneHash) => {
  return prisma.sceneRenderCache.findUnique({
    where: {
      projectId_sceneId_sceneHash: {
        projectId,
        sceneId,
        sceneHash,
      },
    },
  });
};

const upsertSceneRenderCache = ({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  sceneHash,
  s3Key,
  outputUrl,
  metadata,
  fileSizeBytes,
}) => {
  return prisma.sceneRenderCache.upsert({
    where: {
      projectId_sceneId_sceneHash: {
        projectId,
        sceneId,
        sceneHash,
      },
    },
    update: {
      folderId,
      s3Key,
      outputUrl,
      metadata,
      ...(fileSizeBytes != null ? { fileSizeBytes } : {}),
    },
    create: {
      workspaceId,
      folderId,
      projectId,
      sceneId,
      sceneHash,
      s3Key,
      outputUrl,
      metadata,
      fileSizeBytes: fileSizeBytes ?? null,
    },
  });
};

module.exports = {
  createProjectRender,
  updateProjectRender,
  listProjectRenders,
  findProjectRenderById,
  findSceneRenderCache,
  upsertSceneRenderCache,
};
