const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');

async function getWorkspaceOwnerOrThrow(workspaceId) {
  const workspace = await storageDao.getWorkspaceOwnerStorage(workspaceId);
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }
  if (!workspace.owner) {
    throw new AppError(messages.WORKSPACE_OWNER_NOT_FOUND, 404);
  }
  return workspace.owner;
}

async function assertOwnerCanFitAdditionalBytes(workspaceId, additionalBytes) {
  const delta = Math.max(0, Math.floor(Number(additionalBytes) || 0));
  if (delta === 0) return;

  const owner = await getWorkspaceOwnerOrThrow(workspaceId);
  if (owner.storageUsed + delta > owner.storageLimit) {
    throw new AppError(messages.STORAGE_LIMIT_EXCEEDED, 400);
  }
}

async function recalculateUserStorageUsed(ownerId) {
  const user = await storageDao.getUserStorage(ownerId);
  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  const usedBytes = await storageDao.sumOwnerBillableStorageUsed(ownerId);
  await storageDao.prisma.user.update({
    where: { id: ownerId },
    data: {
      storageUsed: usedBytes,
    },
  });

  return usedBytes;
}

module.exports = {
  assertOwnerCanFitAdditionalBytes,
  recalculateUserStorageUsed,
  getWorkspaceOwnerOrThrow,
};
