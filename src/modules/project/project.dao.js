const prisma = require('../../shared/config/prismaClient');

const projectListSelect = {
  id: true,
  name: true,
  workspaceId: true,
  folderId: true,
  createdBy: true,
  updatedBy: true,
  type: true,
  thumbnail: true,
  duration: true,
  status: true,
  storageBytes: true,
  createdAt: true,
  updatedAt: true,
  folder: {
    select: { id: true, name: true },
  },
};

const findFolderById = async (folderId) => {
  return prisma.folder.findUnique({
    where: { id: folderId },
  });
};

const listProjects = async ({ workspaceId, folderId, type }) => {
  return prisma.project.findMany({
    where: {
      workspaceId,
      ...(folderId ? { folderId } : {}),
      ...(type ? { type } : {}),
    },
    select: projectListSelect,
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

const findCoverSourcesByIds = async (ids) => {
  if (!Array.isArray(ids) || ids.length === 0) return [];
  return prisma.project.findMany({
    where: { id: { in: ids } },
    select: {
      id: true,
      type: true,
      data: true,
      thumbnail: true,
      deck: {
        select: {
          slides: {
            orderBy: { order: 'asc' },
            take: 1,
            select: {
              id: true,
              order: true,
              imageRef: true,
              content: true,
              elements: true,
            },
          },
        },
      },
    },
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
  projectListSelect,
  findFolderById,
  listProjects,
  findProjectById,
  findProjectByIdWithAssets,
  createProject,
  updateProject,
  deleteProject,
  findAssetsByIds,
  findCoverSourcesByIds,
  transaction,
};
