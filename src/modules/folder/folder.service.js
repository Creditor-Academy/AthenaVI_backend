const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const folderDao = require('./folder.dao');

async function validateWorkspaceAccess(workspaceId, userId) {
  const workspace = await folderDao.findWorkspaceById(workspaceId);
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }

  const member = await folderDao.findWorkspaceMember(workspaceId, userId);
  if (!member) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  return { workspace, member };
}

function formatFolder(folder) {
  return {
    id: folder.id,
    name: folder.name,
    workspaceId: folder.workspaceId,
    createdBy: folder.createdBy,
    createdAt: folder.createdAt,
  };
}

async function attachCreatorUsers(folders) {
  const creatorIds = [...new Set(folders.map((f) => f.createdBy).filter(Boolean))];
  const users = await folderDao.findUsersByIds(creatorIds);
  const userById = new Map(users.map((u) => [u.id, u]));

  return folders.map((folder) => {
    const formatted = formatFolder(folder);
    const creator = userById.get(folder.createdBy);
    return {
      ...formatted,
      creator: creator
        ? { id: creator.id, name: creator.name, email: creator.email }
        : null,
    };
  });
}

async function listFolders(workspaceId, userId) {
  await validateWorkspaceAccess(workspaceId, userId);
  const folders = await folderDao.listFoldersByWorkspace(workspaceId);
  return attachCreatorUsers(folders);
}

async function createFolder(workspaceId, userId, name) {
  await validateWorkspaceAccess(workspaceId, userId);
  const folder = await folderDao.createFolder({
    name,
    workspaceId,
    createdBy: userId,
  });
  const [withCreator] = await attachCreatorUsers([folder]);
  return withCreator;
}

const renameFolder = async (folderId, name) => {
  const folder = await folderDao.renameFolder(folderId, name);
  const [withCreator] = await attachCreatorUsers([folder]);
  return withCreator;
};

const deleteFolder = async (folderId) => {
  const deletedFolder = await folderDao.deleteFolder(folderId);
  const [withCreator] = await attachCreatorUsers([deletedFolder]);
  return withCreator;
};

module.exports = {
  validateWorkspaceAccess,
  listFolders,
  createFolder,
  renameFolder,
  deleteFolder,
};
