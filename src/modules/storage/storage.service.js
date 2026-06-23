const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const storageLedger = require('./storageLedger.service');
const storageUpgradeRateLimit = require('./storageUpgradeRateLimit.service');
const { sendEmail } = require('../../shared/notification/email.service');
const { buildStorageUpgradeRequestEmail } = require('../../shared/templates/storageUpgradeRequest.template');
const { getPlatformSuperadminNotificationEmails } = require('../../shared/services/platformSuperadmin.service');
const { STORAGE_TIERS, getStorageTierById } = require('../../shared/config/storagePricing');

function serializeStorageUpgradeRequest(record) {
  if (!record) {
    return null;
  }

  return {
    requestId: record.id,
    status: record.status.toLowerCase(),
    requestedAdditionalGb: record.requestedAdditionalGb,
    requestedAdditionalBytes: record.requestedAdditionalBytes,
    reason: record.reason,
    urgency: record.urgency,
    currentUsedBytes: record.currentUsedBytes,
    currentLimitBytes: record.currentLimitBytes,
    tierId: record.tierId,
    tierLabel: record.tierLabel,
    workspaceId: record.workspaceId,
    workspaceName: record.workspaceName,
    workspaceFootprintBytes: record.workspaceFootprintBytes,
    submittedAt: record.createdAt.toISOString(),
    reviewedAt: record.reviewedAt ? record.reviewedAt.toISOString() : null,
    reviewNote: record.reviewNote,
  };
}

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
  const activeUpgradeRequest = await storageDao.findLatestPendingStorageUpgradeRequest(userId);

  return {
    ...serializeStorageSummary(user),
    activeUpgradeRequest: serializeStorageUpgradeRequest(activeUpgradeRequest),
  };
}

async function getUserStorageUpgradeRequests(userId, page, limit, status) {
  const normalizedStatus = status ? String(status).trim().toUpperCase() : undefined;
  const allowedStatuses = ['PENDING', 'APPROVED', 'REJECTED'];
  if (normalizedStatus && !allowedStatuses.includes(normalizedStatus)) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  const result = await storageDao.listStorageUpgradeRequestsByUser(
    userId,
    page,
    limit,
    normalizedStatus
  );

  return {
    requests: result.requests.map(serializeStorageUpgradeRequest),
    pagination: result.pagination,
  };
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

  let result;

  if (tierId) {
    const tier = getStorageTierById(tierId);
    if (!tier) {
      throw new AppError(messages.INVALID_REQUEST, 400);
    }
    result = await storageLedger.platformGrantStorageTier({
      targetUserId,
      limitBytes: tier.limitBytes,
      tierId,
      reason,
      grantedByUserId,
    });
  } else {
    result = await storageLedger.platformGrantStorage({
      targetUserId,
      additionalBytes,
      tierId: null,
      reason,
      grantedByUserId,
    });
  }

  await storageDao.approveLatestPendingStorageUpgradeRequest(
    targetUserId,
    grantedByUserId,
    reason
  );

  return result;
}

async function revokeUserStorage({ targetUserId, amountBytes, reason, revokedByUserId }) {
  return storageLedger.platformRevokeStorage({
    targetUserId,
    amountBytes,
    reason,
    revokedByUserId,
  });
}

function assertRequestedBytesMatchGb(requestedAdditionalGb, requestedAdditionalBytes) {
  const expected = Math.round(requestedAdditionalGb * 1024 ** 3);
  if (Math.abs(requestedAdditionalBytes - expected) > 1) {
    throw new AppError(messages.STORAGE_UPGRADE_BYTES_MISMATCH, 400);
  }
}

async function submitStorageUpgradeRequest(userId, payload) {
  await storageUpgradeRateLimit.assertAllowed(userId);

  const user = await storageDao.getUserStorage(userId);
  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  const {
    requestedAdditionalGb,
    requestedAdditionalBytes,
    reason,
    urgency,
    currentUsedBytes,
    currentLimitBytes,
    tierId,
    tierLabel,
    workspaceId,
    workspaceName,
    workspaceFootprintBytes,
  } = payload;

  assertRequestedBytesMatchGb(requestedAdditionalGb, requestedAdditionalBytes);

  const requestRecord = await storageDao.createStorageUpgradeRequest({
    userId: user.id,
    requestedAdditionalGb,
    requestedAdditionalBytes,
    reason,
    urgency,
    currentUsedBytes,
    currentLimitBytes,
    tierId,
    tierLabel,
    workspaceId,
    workspaceName,
    workspaceFootprintBytes,
    status: 'PENDING',
  });

  const requestId = requestRecord.id;
  const submittedAt = requestRecord.createdAt.toISOString();
  const notificationEmails = getPlatformSuperadminNotificationEmails();
  const { subject, text, html } = buildStorageUpgradeRequestEmail({
    userName: user.name,
    userEmail: user.email,
    requestedAdditionalGb,
    requestedAdditionalBytes,
    urgency,
    reason,
    currentUsedBytes,
    currentLimitBytes,
    tierId,
    tierLabel,
    workspaceId,
    workspaceName,
    workspaceFootprintBytes,
    submittedAt,
    requestId,
  });

  await sendEmail({
    to: notificationEmails.join(', '),
    subject,
    text,
    html,
  });

  await storageUpgradeRateLimit.recordSuccess(userId);

  return {
    requestId,
    submittedAt,
    status: 'pending',
  };
}

module.exports = {
  getUserStorageSummary,
  getUserStorageHistory,
  getUserStorageUpgradeRequests,
  getWorkspaceStorageSummary,
  grantUserStorage,
  revokeUserStorage,
  submitStorageUpgradeRequest,
};
