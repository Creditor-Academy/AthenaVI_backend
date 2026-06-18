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

const findProjectRenderByIdOnly = (renderId) => {
  return prisma.projectRender.findUnique({
    where: { id: renderId },
  });
};

const listWorkspaceRenders = (workspaceId, { take, skip, status }) => {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);
  return prisma.projectRender.findMany({
    where: {
      workspaceId,
      ...(status ? { status } : {}),
    },
    orderBy: {
      completedAt: 'desc',
    },
    take: limit,
    skip: offset,
    include: {
      project: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  });
};

const listOwnerWorkspaceRenders = (ownerId, { take, skip, status }) => {
  const limit = Math.min(Math.max(Number(take) || 20, 1), 100);
  const offset = Math.max(Number(skip) || 0, 0);
  return prisma.projectRender.findMany({
    where: {
      workspace: { ownerId },
      ...(status ? { status } : {}),
    },
    orderBy: {
      completedAt: 'desc',
    },
    take: limit,
    skip: offset,
    include: {
      project: {
        select: {
          id: true,
          name: true,
          workspaceId: true,
        },
      },
      workspace: {
        select: {
          id: true,
          name: true,
        },
      },
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
  findProjectRenderByIdOnly,
  listWorkspaceRenders,
  listOwnerWorkspaceRenders,
  findSceneRenderCache,
  upsertSceneRenderCache,
};
