const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const storageDao = require('./storage.dao');
const storageLedger = require('./storageLedger.service');
const storageUpgradeRateLimit = require('./storageUpgradeRateLimit.service');
const { sendEmail } = require('../../shared/notification/email.service');
const { buildStorageUpgradeRequestEmail } = require('../../shared/templates/storageUpgradeRequest.template');
const { getPlatformSuperadminNotificationEmails } = require('../../shared/services/platformSuperadmin.service');
const { STORAGE_TIERS, getStorageTierById } = require('../../shared/config/storagePricing');
const { toBigInt, toJsonNumber } = require('../../shared/utils/byteSize');

function serializeStorageTransaction(transaction) {
  if (!transaction) {
    return null;
  }

  return {
    ...transaction,
    amountBytes: toJsonNumber(transaction.amountBytes),
  };
}

function serializeStorageUpgradeRequest(record) {
  if (!record) {
    return null;
  }

  return {
    requestId: record.id,
    status: record.status.toLowerCase(),
    requestedAdditionalGb: record.requestedAdditionalGb,
    requestedAdditionalBytes: toJsonNumber(record.requestedAdditionalBytes),
    reason: record.reason,
    urgency: record.urgency,
    currentUsedBytes: toJsonNumber(record.currentUsedBytes),
    currentLimitBytes: toJsonNumber(record.currentLimitBytes),
    tierId: record.tierId,
    tierLabel: record.tierLabel,
    workspaceId: record.workspaceId,
    workspaceName: record.workspaceName,
    workspaceFootprintBytes:
      record.workspaceFootprintBytes == null
        ? null
        : toJsonNumber(record.workspaceFootprintBytes),
    submittedAt: record.createdAt.toISOString(),
    reviewedAt: record.reviewedAt ? record.reviewedAt.toISOString() : null,
    reviewNote: record.reviewNote,
  };
}

function serializeStorageSummary(user) {
  const usedBytes = toJsonNumber(user.storageUsed);
  const limitBytes = toJsonNumber(user.storageLimit);
  const availableBytes = Math.max(0, limitBytes - usedBytes);
  const percentUsed = limitBytes > 0 ? Number(((usedBytes / limitBytes) * 100).toFixed(2)) : 0;
  const tier =
    STORAGE_TIERS.find((item) => item.limitBytes === limitBytes) ||
    STORAGE_TIERS.find((item) => toBigInt(item.limitBytes) === toBigInt(user.storageLimit)) ||
    null;

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
  const result = await storageDao.listStorageTransactionsByUser(
    userId,
    page,
    limit,
    type || undefined
  );

  return {
    transactions: result.transactions.map(serializeStorageTransaction),
    pagination: result.pagination,
  };
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

  return {
    user: result.user,
    transaction: serializeStorageTransaction(result.transaction),
  };
}

async function revokeUserStorage({ targetUserId, amountBytes, reason, revokedByUserId }) {
  const result = await storageLedger.platformRevokeStorage({
    targetUserId,
    amountBytes,
    reason,
    revokedByUserId,
  });

  return {
    user: result.user,
    transaction: serializeStorageTransaction(result.transaction),
  };
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
    requestedAdditionalBytes: toBigInt(requestedAdditionalBytes),
    reason,
    urgency,
    currentUsedBytes: toBigInt(currentUsedBytes),
    currentLimitBytes: toBigInt(currentLimitBytes),
    tierId,
    tierLabel,
    workspaceId,
    workspaceName,
    workspaceFootprintBytes:
      workspaceFootprintBytes == null ? null : toBigInt(workspaceFootprintBytes),
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

  const inboxService = require('../inbox/inbox.service');
  inboxService
    .notifyPlatformStorageUpgradeRequest({
      requestId,
      userId: user.id,
      userEmail: user.email,
      userName: user.name,
      requestedAdditionalGb,
      urgency,
      reason,
    })
    .catch((error) => console.error('Storage upgrade platform notification failed:', error));

  await storageUpgradeRateLimit.recordSuccess(userId);

  return {
    requestId,
    submittedAt,
    status: 'pending',
  };
}

async function listStorageUpgradeRequestsForAdmin(page, limit, status) {
  const normalizedStatus = status ? String(status).trim().toUpperCase() : undefined;
  const allowedStatuses = ['PENDING', 'APPROVED', 'REJECTED'];
  if (normalizedStatus && !allowedStatuses.includes(normalizedStatus)) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  const result = await storageDao.listStorageUpgradeRequests({
    page,
    limit,
    status: normalizedStatus,
  });

  return {
    requests: result.requests.map((record) => ({
      ...serializeStorageUpgradeRequest(record),
      user: record.user
        ? { id: record.user.id, email: record.user.email, name: record.user.name }
        : null,
    })),
    pagination: result.pagination,
  };
}

async function rejectStorageUpgradeRequest({ requestId, reviewedByUserId, reviewNote }) {
  const result = await storageDao.rejectStorageUpgradeRequest({
    requestId,
    reviewedByUserId,
    reviewNote,
  });

  if (!result) {
    throw new AppError(messages.STORAGE_UPGRADE_REQUEST_NOT_FOUND, 404);
  }
  if (result.error === 'not_pending') {
    throw new AppError(messages.STORAGE_UPGRADE_REQUEST_NOT_PENDING, 400);
  }

  const inboxService = require('../inbox/inbox.service');
  const { request } = result;
  inboxService
    .notifyStorageUpgradeRejected({
      userId: request.userId,
      requestedAdditionalGb: request.requestedAdditionalGb,
      reviewNote,
    })
    .catch((error) => console.error('Storage upgrade rejection notification failed:', error));

  return {
    request: {
      ...serializeStorageUpgradeRequest(request),
      user: request.user
        ? { id: request.user.id, email: request.user.email, name: request.user.name }
        : null,
    },
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
  listStorageUpgradeRequestsForAdmin,
  rejectStorageUpgradeRequest,
};
