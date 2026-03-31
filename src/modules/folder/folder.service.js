const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const folderDao = require('./folder.dao');

// async function validateWorkspaceAccess(workspaceId, userId) {
//   const workspace = await folderDao.findWorkspaceById(workspaceId);
//   if (!workspace) {
//     throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
//   }

//   const member = await folderDao.findWorkspaceMember(workspaceId, userId);
//   if (!member) {
//     throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
//   }

//   return { workspace, member };
// }

async function listFolders(workspaceId, userId) {
//   await validateWorkspaceAccess(workspaceId, userId);

    const folders = await prisma.folder.findMany({
    where: { workspaceId },
    orderBy: { createdAt: 'desc' },
  });

  // Folder persistence is not implemented yet.
  return folders;}

async function createFolder(workspaceId, userId, name) {
  //   await validateWorkspaceAccess(workspaceId, userId);
  const folder = await prisma.folder.create({
    data: {
      name,
      workspaceId,
      createdBy: userId,
    },
  });
  return { id: folder.id, name: folder.name, createdAt: folder.createdAt };
}

const renameFolder = async (folderId, name) => {
  const folder = await folderDao.renameFolder(folderId, name);
  return folder;
}

const deleteFolder = async (folderId) => {
  const deletedFolder =  await folderDao.deleteFolder(folderId);
  return deletedFolder;
}

module.exports = {
  // validateWorkspaceAccess,
  listFolders,
  createFolder,
  renameFolder,
  deleteFolder
};
