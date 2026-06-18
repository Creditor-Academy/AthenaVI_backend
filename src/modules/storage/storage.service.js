const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const storageLedger = require('./storageLedger.service');
const { STORAGE_TIERS, getStorageTierById } = require('../../shared/config/storagePricing');

function serializeStorageSummary(user) {
  const usedBytes = user.storageUsed || 0;
  const limitBytes = user.storageLimit || 0;
  const availableBytes = Math.max(0, limitBytes - usedBytes);
  const percentUsed = limitBytes > 0 ? Number(((usedBytes / limitBytes) * 100).toFixed(2)) : 0;
  const tier = STORAGE_TIERS.find((item) => item.limitBytes === limitBytes) || null;

  return {
    userId: user.id,
    limitBytes,
    usedBytes,
    availableBytes,
    percentUsed,
    tier: tier ? { id: tier.id, label: tier.label } : null,
  };
}

async function getUserStorageSummary(userId) {
  const user = await storageLedger.getUserStorageOrThrow(userId);
  return serializeStorageSummary(user);
}

async function getUserStorageHistory(userId, page, limit, type) {
  return storageDao.listStorageTransactionsByUser(userId, page, limit, type || undefined);
}

async function getWorkspaceStorageSummary(workspaceId) {
  const workspace = await storageDao.getWorkspaceOwnerStorage(workspaceId);
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }
  if (!workspace.owner) {
    throw new AppError(messages.WORKSPACE_OWNER_NOT_FOUND, 404);
  }

  const footprint = await storageDao.sumWorkspaceStorageFootprint(workspaceId);

  return {
    workspaceId: workspace.id,
    workspaceType: workspace.type,
    owner: {
      id: workspace.owner.id,
      email: workspace.owner.email,
      name: workspace.owner.name,
    },
    quota: serializeStorageSummary(workspace.owner),
    footprint: {
      ...footprint,
      totalBytes: footprint.assetBytes + footprint.heygenBytes + footprint.renderBytes,
    },
  };
}

async function grantUserStorage({ targetUserId, tierId, additionalBytes, reason, grantedByUserId }) {
  if (!tierId && !additionalBytes) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  if (tierId) {
    const tier = getStorageTierById(tierId);
    if (!tier) {
      throw new AppError(messages.INVALID_REQUEST, 400);
    }
    return storageLedger.platformGrantStorageTier({
      targetUserId,
      limitBytes: tier.limitBytes,
      tierId,
      reason,
      grantedByUserId,
    });
  }

  return storageLedger.platformGrantStorage({
    targetUserId,
    additionalBytes,
    tierId: null,
    reason,
    grantedByUserId,
  });
}

async function revokeUserStorage({ targetUserId, amountBytes, reason, revokedByUserId }) {
  return storageLedger.platformRevokeStorage({
    targetUserId,
    amountBytes,
    reason,
    revokedByUserId,
  });
}

module.exports = {
  getUserStorageSummary,
  getUserStorageHistory,
  getWorkspaceStorageSummary,
  grantUserStorage,
  revokeUserStorage,
};
