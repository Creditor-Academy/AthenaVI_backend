const prisma = require('../../shared/config/prismaClient');

const folderSelect = {
  id: true,
  name: true,
  workspaceId: true,
  createdBy: true,
  createdAt: true,
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

const createFolder = async ({ name, workspaceId, createdBy }) => {
  return prisma.folder.create({
    data: { name, workspaceId, createdBy },
    select: folderSelect,
  });
};

const findUsersByIds = async (userIds) => {
  if (!userIds.length) return [];
  return prisma.user.findMany({
    where: { id: { in: userIds } },
    select: { id: true, name: true, email: true },
  });
};

const renameFolder = async (folderId, name) => {
  return prisma.folder.update({
    where: { id: folderId },
    data: { name },
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
  createFolder,
  findUsersByIds,
  renameFolder,
  deleteFolder,
};
