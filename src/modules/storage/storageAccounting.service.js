const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const inboxService = require('../inbox/inbox.service');
const { toBigInt, toJsonNumber, byteGt, byteAdd } = require('../../shared/utils/byteSize');

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
  const delta = toBigInt(additionalBytes);
  if (delta <= 0n) return;

  const owner = await getWorkspaceOwnerOrThrow(workspaceId);
  if (byteGt(byteAdd(owner.storageUsed, delta), owner.storageLimit)) {
    throw new AppError(messages.STORAGE_LIMIT_EXCEEDED, 400);
  }
}

async function recalculateUserStorageUsed(ownerId) {
  const user = await storageDao.getUserStorage(ownerId);
  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  const usedBytes = await storageDao.sumOwnerBillableStorageUsed(ownerId);
  const limitBytes = toJsonNumber(user.storageLimit);

  await storageDao.prisma.user.update({
    where: { id: ownerId },
    data: {
      storageUsed: toBigInt(usedBytes),
    },
  });

  inboxService
    .maybeNotifyStorageThreshold({
      userId: ownerId,
      usedBytes,
      limitBytes,
    })
    .catch((error) => console.error('Storage threshold notification failed:', error));

  return usedBytes;
}

module.exports = {
  assertOwnerCanFitAdditionalBytes,
  recalculateUserStorageUsed,
  getWorkspaceOwnerOrThrow,
};
