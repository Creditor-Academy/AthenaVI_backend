const prisma = require('../shared/config/prismaClient');
const AppError = require('../shared/utils/AppError');
const asyncHandler = require('../shared/utils/asyncHandler');
const messages = require('../shared/utils/messages');

const folderPermission = asyncHandler(async (req, res, next) => {
  const userId = req.user.id;
  const folderId = req.params.folderId;

  const folder = await prisma.folder.findUnique({
    where: { id: folderId },
  });

  if (!folder) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }

  // check membership
  const member = await prisma.workspaceMember.findUnique({
    where: {
      workspaceId_userId: {
        workspaceId: folder.workspaceId,
        userId,
      },
    },
  });
  if (!member) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  // permission check
  const isOwnerOrAdmin = member.role === 'owner' || member.role === 'admin';

  const isCreator = folder.createdBy === userId;

  if (!isCreator && !isOwnerOrAdmin) {
    throw new AppError(messages.FOLDER_FORBIDDEN, 403);
  }
  req.folder = folder;

  next();
});


module.exports = {
  folderPermission,
};