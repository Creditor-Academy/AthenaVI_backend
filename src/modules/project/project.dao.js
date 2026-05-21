const prisma = require('../../shared/config/prismaClient');

const findFolderById = async (folderId) => {
  return prisma.folder.findUnique({
    where: { id: folderId },
  });
};

const listProjects = async ({ workspaceId, folderId }) => {
  return prisma.project.findMany({
    where: {
      workspaceId,
      ...(folderId ? { folderId } : {}),
    },
    include: {
      folder: {
        select: { id: true, name: true },
      },
    },
    orderBy: { updatedAt: 'desc' },
  });
};

const findProjectById = async (workspaceId, projectId) => {
  return prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    include: {
      folder: {
        select: { id: true, name: true, workspaceId: true },
      },
    },
  });
};

const findProjectByIdWithAssets = async (workspaceId, projectId) => {
  return prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    include: {
      folder: true,
      heygenResponses: true,
      projectRenders: true,
      sceneRenderCaches: true,
    },
  });
};

const createProject = async (projectData) => {
  return prisma.project.create({
    data: projectData,
    include: {
      folder: {
        select: { id: true, name: true },
      },
    },
  });
};

const updateProject = async (projectId, data) => {
  return prisma.project.update({
    where: { id: projectId },
    data,
    include: {
      folder: {
        select: { id: true, name: true },
      },
    },
  });
};

const deleteProject = async (projectId) => {
  return prisma.project.delete({
    where: { id: projectId },
  });
};

const findAssetsByIds = async (workspaceId, assetIds) => {
  if (!assetIds.length) {
    return [];
  }

  return prisma.asset.findMany({
    where: {
      workspaceId,
      id: {
        in: assetIds,
      },
    },
  });
};

const transaction = (fn) => prisma.$transaction(fn);

module.exports = {
  findFolderById,
  listProjects,
  findProjectById,
  findProjectByIdWithAssets,
  createProject,
  updateProject,
  deleteProject,
  findAssetsByIds,
  transaction,
};
