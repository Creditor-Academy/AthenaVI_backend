const prisma = require('../../shared/config/prismaClient');

const folderSelect = {
  id: true,
  name: true,
  workspaceId: true,
  createdBy: true,
  updatedBy: true,
  createdAt: true,
  updatedAt: true,
};

const findWorkspaceById = async (workspaceId) => {
  return prisma.workspace.findUnique({
    where: { id: workspaceId },
  });
};

const findWorkspaceMember = async (workspaceId, userId) => {
  return prisma.workspaceMember.findUnique({
    where: {
      workspaceId_userId: { workspaceId, userId },
    },
    select: {
      id: true,
      role: true,
    },
  });
};

const listFoldersByWorkspace = async (workspaceId) => {
  return prisma.folder.findMany({
    where: { workspaceId },
    select: folderSelect,
    orderBy: { createdAt: 'desc' },
  });
};

const getFolderProjectStatsByWorkspace = async (workspaceId) => {
  return prisma.project.groupBy({
    by: ['folderId'],
    where: { workspaceId },
    _count: { id: true },
    _sum: { storageBytes: true },
    _max: { updatedAt: true },
  });
};

const createFolder = async ({ name, workspaceId, createdBy, updatedBy }) => {
  return prisma.folder.create({
    data: { name, workspaceId, createdBy, updatedBy: updatedBy ?? createdBy },
    select: folderSelect,
  });
};

const renameFolder = async (folderId, name, updatedBy) => {
  return prisma.folder.update({
    where: { id: folderId },
    data: { name, updatedBy },
    select: folderSelect,
  });
};

const deleteFolder = async (folderId) => {
  return prisma.folder.delete({
    where: { id: folderId },
    select: folderSelect,
  });
};

module.exports = {
  folderSelect,
  findWorkspaceById,
  findWorkspaceMember,
  listFoldersByWorkspace,
  getFolderProjectStatsByWorkspace,
  createFolder,
  renameFolder,
  deleteFolder,
};
