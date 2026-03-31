const prisma = require('../../shared/config/prismaClient');

const findWorkspaceById = async (workspaceId) => {
  return await prisma.workspace.findUnique({
    where: { id: workspaceId },
  });
};

const findWorkspaceMember = async (workspaceId, userId) => {
  return await prisma.workspaceMember.findUnique({
    where: {
      workspaceId_userId: { workspaceId, userId },
    },
    select: {
      id: true,
      role: true,
    },
  });
};


const renameFolder = async (folderId, name) => {
  const folder = await prisma.folder.update({
    where: { id: folderId },data: { name },
  });
  return folder;
}

const deleteFolder = async (folderId) => {
  const deletedFolder = await prisma.folder.delete({
    where: { id: folderId },
  });
  return deletedFolder;
}

module.exports = {
  findWorkspaceById,
  findWorkspaceMember,
  renameFolder,
  deleteFolder,
};
