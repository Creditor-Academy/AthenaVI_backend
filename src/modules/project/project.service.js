const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('./project.dao');

const createProject = async (
  workspaceId,
  userId,
  name,
  folderId,
  projectState,
  thumbnail,
  duration,
  status
) => {
  const folder = await projectDao.findFolderById(folderId);

  if (!folder || folder.workspaceId !== workspaceId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }

  const project = await projectDao.createProject({
    name,
    workspaceId,
    folderId,
    createdBy: userId,
    data: projectState || {},
    thumbnail,
    duration,
    status: status ?? 'draft',
  });

  return project;
};

module.exports = {
  createProject,
};
