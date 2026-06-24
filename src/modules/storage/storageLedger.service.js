const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const inboxService = require('../inbox/inbox.service');
const {
  toBigInt,
  toJsonNumber,
  byteLt,
  byteSub,
} = require('../../shared/utils/byteSize');

function toWholeBytes(value) {
  return toBigInt(value);
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
    amountBytes: toBigInt(limitBytes),
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
  if (delta <= 0n) {
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
        amountBytes: toJsonNumber(delta),
        reason,
      })
      .catch((error) => console.error('Storage grant notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: toJsonNumber(result.user.storageUsed),
        limitBytes: toJsonNumber(result.user.storageLimit),
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
  if (nextLimit <= 0n) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  const user = await getUserStorageOrThrow(targetUserId);
  if (byteLt(nextLimit, user.storageUsed)) {
    throw new AppError(messages.STORAGE_REVOKE_BELOW_USED, 400);
  }

  const delta = byteSub(nextLimit, user.storageLimit);

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
        previousLimitBytes: toJsonNumber(user.storageLimit),
        nextLimitBytes: toJsonNumber(nextLimit),
      },
    });
    return { user: updated, transaction };
  }).then(async (result) => {
    inboxService
      .notifyStoragePlatformGrant({
        userId: targetUserId,
        amountBytes: toJsonNumber(delta > 0n ? delta : 0n),
        reason,
      })
      .catch((error) => console.error('Storage grant notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: toJsonNumber(result.user.storageUsed),
        limitBytes: toJsonNumber(result.user.storageLimit),
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
  if (delta <= 0n) {
    throw new AppError(messages.INVALID_STORAGE_AMOUNT, 400);
  }

  const user = await getUserStorageOrThrow(targetUserId);
  const nextLimit = byteSub(user.storageLimit, delta);
  if (byteLt(nextLimit, user.storageUsed)) {
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
        amountBytes: toJsonNumber(delta),
        reason,
      })
      .catch((error) => console.error('Storage revoke notification failed:', error));
    inboxService
      .maybeNotifyStorageThreshold({
        userId: targetUserId,
        usedBytes: toJsonNumber(result.user.storageUsed),
        limitBytes: toJsonNumber(result.user.storageLimit),
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
