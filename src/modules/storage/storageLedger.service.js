const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const inboxService = require('../inbox/inbox.service');

function toWholeBytes(value) {
  return Math.floor(Number(value) || 0);
}

async function getUserStorageOrThrow(userId) {
  const user = await storageDao.getUserStorage(userId);
  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }
  return user;
}

async function recordInitialStorageGrant(tx, { userId, limitBytes, tierId }) {
  return storageDao.createStorageTransaction(tx, {
    userId,
    amountBytes: limitBytes,
    type: 'initial',
    tierId: tierId || null,
    metadata: {
      source: 'registration',
    },
  });
}

async function platformGrantStorage({
  targetUserId,
  additionalBytes,
  tierId,
  reason,
  grantedByUserId,
}) {
  const delta = toWholeBytes(additionalBytes);
  if (delta <= 0) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  await getUserStorageOrThrow(targetUserId);

  return storageDao.prisma.$transaction(async (tx) => {
    const user = await storageDao.incrementUserStorageLimit(tx, targetUserId, delta);
    const transaction = await storageDao.createStorageTransaction(tx, {
      userId: targetUserId,
      amountBytes: delta,
      type: 'platform_grant',
      tierId: tierId || null,
      reference: reason || null,
      metadata: {
        grantedByUserId,
        reason: reason || null,
        mode: 'increment',
      },
    });
    return { user, transaction };
  }).then(async (result) => {
    inboxService
      .notifyStoragePlatformGrant({
        userId: targetUserId,
        amountBytes: delta,
        reason,
      })
      .catch((error) => console.error('Storage grant notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: result.user.storageUsed,
        limitBytes: result.user.storageLimit,
      })
      .catch((error) => console.error('Storage threshold notification failed:', error));
    return result;
  });
}

async function platformGrantStorageTier({
  targetUserId,
  limitBytes,
  tierId,
  reason,
  grantedByUserId,
}) {
  const nextLimit = toWholeBytes(limitBytes);
  if (nextLimit <= 0) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  const user = await getUserStorageOrThrow(targetUserId);
  if (nextLimit < user.storageUsed) {
    throw new AppError(messages.STORAGE_REVOKE_BELOW_USED, 400);
  }

  const delta = nextLimit - user.storageLimit;

  return storageDao.prisma.$transaction(async (tx) => {
    const updated = await storageDao.updateUserStorageLimit(tx, targetUserId, nextLimit);
    const transaction = await storageDao.createStorageTransaction(tx, {
      userId: targetUserId,
      amountBytes: delta,
      type: 'platform_grant',
      tierId: tierId || null,
      reference: reason || null,
      metadata: {
        grantedByUserId,
        reason: reason || null,
        mode: 'tier_set',
        previousLimitBytes: user.storageLimit,
        nextLimitBytes: nextLimit,
      },
    });
    return { user: updated, transaction };
  }).then(async (result) => {
    inboxService
      .notifyStoragePlatformGrant({
        userId: targetUserId,
        amountBytes: Math.max(delta, 0),
        reason,
      })
      .catch((error) => console.error('Storage grant notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: result.user.storageUsed,
        limitBytes: result.user.storageLimit,
      })
      .catch((error) => console.error('Storage threshold notification failed:', error));
    return result;
  });
}

async function platformRevokeStorage({
  targetUserId,
  amountBytes,
  reason,
  revokedByUserId,
}) {
  const delta = toWholeBytes(amountBytes);
  if (delta <= 0) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  const user = await getUserStorageOrThrow(targetUserId);
  const nextLimit = user.storageLimit - delta;
  if (nextLimit < user.storageUsed) {
    throw new AppError(messages.STORAGE_REVOKE_BELOW_USED, 400);
  }

  return storageDao.prisma.$transaction(async (tx) => {
    const updated = await storageDao.updateUserStorageLimit(tx, targetUserId, nextLimit);
    const transaction = await storageDao.createStorageTransaction(tx, {
      userId: targetUserId,
      amountBytes: -delta,
      type: 'platform_revoke',
      reference: reason || null,
      metadata: {
        revokedByUserId,
        reason: reason || null,
      },
    });
    return { user: updated, transaction };
  }).then(async (result) => {
    inboxService
      .notifyStoragePlatformRevoke({
        userId: targetUserId,
        amountBytes: delta,
        reason,
      })
      .catch((error) => console.error('Storage revoke notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: result.user.storageUsed,
        limitBytes: result.user.storageLimit,
      })
      .catch((error) => console.error('Storage threshold notification failed:', error));
    return result;
  });
}

module.exports = {
  getUserStorageOrThrow,
  recordInitialStorageGrant,
  platformGrantStorage,
  platformGrantStorageTier,
  platformRevokeStorage,
};
