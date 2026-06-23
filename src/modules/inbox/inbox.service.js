const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const {
  CREDITS_LOW_THRESHOLD_AC,
  STORAGE_THRESHOLD_PERCENTS,
} = require('../../shared/config/notificationThresholds');
const { DEFAULT_NOTIFICATIONS } = require('../settings/notifications.constants');
const settingsDao = require('../settings/settings.dao');
const inboxDao = require('./inbox.dao');
const {
  getCategoryForType,
  getPreferenceKeyForType,
  getTypesForCategory,
  buildActionUrl,
  serializeNotification,
  CATEGORIES,
} = require('./inbox.notificationTypes');

function buildInvitationActionUrl(token) {
  return `${process.env.FRONTEND_URL}/invitations/accept/${token}`;
}

function formatWorkspaceInvitationNotification({ invitation, workspace, inviter }) {
  const workspaceName = workspace.name;
  const roleLabel = invitation.role;
  const actionUrl = buildInvitationActionUrl(invitation.token);

  return {
    type: 'WORKSPACE_INVITATION',
    title: `Invitation to ${workspaceName}`,
    message: `You have been invited to join ${workspaceName} as ${roleLabel}.`,
    metadata: {
      invitationId: invitation.id,
      workspaceId: workspace.id,
      workspaceName,
      role: invitation.role,
      token: invitation.token,
      actionUrl,
      inviterName: inviter?.name || null,
      expiresAt: invitation.expiresAt,
    },
  };
}

async function getNotificationPreferences(userId) {
  const settings = await settingsDao.findByUserId(userId);
  if (!settings) {
    return { ...DEFAULT_NOTIFICATIONS };
  }
  return {
    pushNotifications: settings.pushNotifications,
    commentsAndMentions: settings.commentsAndMentions,
    weeklyDigestEmail: settings.weeklyDigestEmail,
    productEmails: settings.productEmails,
    videoExportAlerts: settings.videoExportAlerts,
    workspaceVideoExportAlerts: settings.workspaceVideoExportAlerts,
    creditsAlerts: settings.creditsAlerts,
    storageAlerts: settings.storageAlerts,
    workspaceTeamAlerts: settings.workspaceTeamAlerts,
    platformAdminAlerts: settings.platformAdminAlerts,
  };
}

async function shouldNotifyUser(userId, type, metadata = {}) {
  const prefs = await getNotificationPreferences(userId);
  if (!prefs.pushNotifications) {
    return false;
  }
  const key = getPreferenceKeyForType(type, metadata);
  if (key === 'pushNotifications') {
    return true;
  }
  return prefs[key] !== false;
}

async function notifyUser({
  userId,
  type,
  referenceId,
  workspaceId,
  title,
  message,
  metadata = {},
}) {
  const enrichedMetadata = {
    ...metadata,
    actionUrl: metadata.actionUrl || buildActionUrl(metadata),
  };

  if (!(await shouldNotifyUser(userId, type, enrichedMetadata))) {
    return null;
  }

  const row = await inboxDao.upsertNotification({
    userId,
    type,
    referenceId,
    workspaceId: workspaceId || metadata.workspaceId || null,
    title,
    message,
    metadata: enrichedMetadata,
    invitationId: metadata.invitationId || null,
  });

  return serializeNotification(row);
}

async function notifyMany(userIds, payload) {
  const uniqueIds = [...new Set(userIds.filter(Boolean))];
  const results = await Promise.all(
    uniqueIds.map((userId) => notifyUser({ userId, ...payload }))
  );
  return results.filter(Boolean);
}

async function notifyWorkspaceAdmins({
  workspaceId,
  excludeUserId,
  type,
  referenceId,
  title,
  message,
  metadata = {},
}) {
  const members = await inboxDao.findWorkspaceAdminsAndOwners(workspaceId);
  const userIds = members
    .map((m) => m.userId)
    .filter((id) => id !== excludeUserId);

  return notifyMany(userIds, {
    type,
    referenceId,
    workspaceId,
    title,
    message,
    metadata: { ...metadata, audience: 'workspace_admin' },
  });
}

async function notifyWorkspaceInvitation({ userId, invitation, workspace, inviter }) {
  if (!invitation?.id || !workspace) return null;

  const payload = formatWorkspaceInvitationNotification({
    invitation,
    workspace,
    inviter,
  });

  const row = await inboxDao.upsertWorkspaceInvitationNotification({
    userId,
    invitationId: invitation.id,
    workspaceId: workspace.id,
    ...payload,
  });

  return serializeNotification(row);
}

async function syncPendingWorkspaceInvitations(userId, email) {
  const normalizedEmail = email.trim().toLowerCase();
  const invitations = await inboxDao.findPendingInvitationsByEmail(normalizedEmail);

  await Promise.all(
    invitations.map((invitation) =>
      notifyWorkspaceInvitation({
        userId,
        invitation,
        workspace: invitation.workspace,
        inviter: null,
      })
    )
  );
}

async function removeInvitationNotifications(invitationId) {
  await inboxDao.deleteByInvitationId(invitationId);
}

async function markInvitationNotificationRead(userId, invitationId) {
  await inboxDao.markReadByInvitationForUser(userId, invitationId);
}

function buildVideoExportCopy({
  status,
  projectName,
  triggeredByName,
  audience,
}) {
  const label = projectName ? `"${projectName}"` : 'your project';
  if (status === 'completed') {
    if (audience === 'workspace_admin') {
      return {
        title: `${triggeredByName || 'A member'} exported ${label}`,
        message: `Final video export completed in your workspace.`,
      };
    }
    return {
      title: `${label} export is ready`,
      message: 'Your final video finished rendering and is ready to download.',
    };
  }

  if (audience === 'workspace_admin') {
    return {
      title: `${triggeredByName || 'A member'}'s export failed`,
      message: `Final video export for ${label} failed in your workspace.`,
    };
  }
  return {
    title: `${label} export failed`,
    message: 'Your final video export failed. Open the project to try again.',
  };
}

async function notifyVideoExportFinished({
  renderId,
  workspaceId,
  projectId,
  userId,
  status,
  projectName,
  workspaceName,
  workspaceType,
  triggeredByName,
  creditsCharged,
  error,
}) {
  const type =
    status === 'completed' ? 'VIDEO_EXPORT_COMPLETED' : 'VIDEO_EXPORT_FAILED';
  const baseMetadata = {
    workspaceId,
    workspaceName,
    workspaceType,
    projectId,
    projectName,
    renderId,
    status,
    triggeredByUserId: userId,
    triggeredByName: triggeredByName || null,
    creditsCharged: creditsCharged ?? null,
    error: error || null,
  };

  const recipientIds = new Set([userId]);

  if (workspaceType === 'TEAM') {
    const admins = await inboxDao.findWorkspaceAdminsAndOwners(workspaceId);
    admins.forEach((m) => recipientIds.add(m.userId));
  }

  await Promise.all(
    [...recipientIds].map(async (recipientId) => {
      const audience = recipientId === userId ? 'self' : 'workspace_admin';
      const copy = buildVideoExportCopy({
        status,
        projectName,
        triggeredByName,
        audience,
      });

      return notifyUser({
        userId: recipientId,
        type,
        referenceId: renderId,
        workspaceId,
        title: copy.title,
        message: copy.message,
        metadata: { ...baseMetadata, audience },
      });
    })
  );
}

async function maybeNotifyCreditsLow({ userId, workspaceId, pool, balance }) {
  const credits = Math.floor(Number(balance) || 0);

  if (pool === 'user') {
    if (credits >= CREDITS_LOW_THRESHOLD_AC) {
      await inboxDao.deleteByUserTypeReference(userId, 'CREDITS_LOW_PERSONAL', 'low_personal');
      return null;
    }

    return notifyUser({
      userId,
      type: 'CREDITS_LOW_PERSONAL',
      referenceId: 'low_personal',
      title: 'Personal credits running low',
      message: `You have ${credits} AC remaining. Top up or allocate credits to continue.`,
      metadata: { balance: credits, threshold: CREDITS_LOW_THRESHOLD_AC },
    });
  }

  if (pool === 'workspace' && workspaceId) {
    const referenceId = `low_workspace_${workspaceId}`;

    if (credits >= CREDITS_LOW_THRESHOLD_AC) {
      const admins = await inboxDao.findWorkspaceAdminsAndOwners(workspaceId);
      await Promise.all(
        admins.map((m) =>
          inboxDao.deleteByUserTypeReference(m.userId, 'CREDITS_LOW_WORKSPACE', referenceId)
        )
      );
      return null;
    }

    const admins = await inboxDao.findWorkspaceAdminsAndOwners(workspaceId);
    return notifyMany(
      admins.map((m) => m.userId),
      {
        type: 'CREDITS_LOW_WORKSPACE',
        referenceId,
        workspaceId,
        title: 'Workspace credits running low',
        message: `Workspace pool has ${credits} AC remaining.`,
        metadata: {
          workspaceId,
          balance: credits,
          threshold: CREDITS_LOW_THRESHOLD_AC,
          audience: 'workspace_admin',
        },
      }
    );
  }

  return null;
}

async function maybeNotifyStorageThreshold({ userId, usedBytes, limitBytes }) {
  const used = Math.max(0, Math.floor(Number(usedBytes) || 0));
  const limit = Math.max(1, Math.floor(Number(limitBytes) || 1));
  const percentUsed = (used / limit) * 100;

  let activeThreshold = null;
  for (const threshold of STORAGE_THRESHOLD_PERCENTS) {
    if (percentUsed >= threshold) {
      activeThreshold = threshold;
    }
  }

  if (!activeThreshold) {
    for (const threshold of STORAGE_THRESHOLD_PERCENTS) {
      await inboxDao.deleteByUserTypeReference(
        userId,
        'STORAGE_THRESHOLD_WARNING',
        `storage_${userId}_${threshold}`
      );
    }
    return null;
  }

  for (const threshold of STORAGE_THRESHOLD_PERCENTS) {
    if (threshold !== activeThreshold) {
      await inboxDao.deleteByUserTypeReference(
        userId,
        'STORAGE_THRESHOLD_WARNING',
        `storage_${userId}_${threshold}`
      );
    }
  }

  const title =
    activeThreshold >= 100
      ? 'Storage quota full'
      : `Storage ${activeThreshold}% full`;

  return notifyUser({
    userId,
    type: 'STORAGE_THRESHOLD_WARNING',
    referenceId: `storage_${userId}_${activeThreshold}`,
    title,
    message: `You are using ${percentUsed.toFixed(1)}% of your storage quota.`,
    metadata: {
      usedBytes: used,
      limitBytes: limit,
      percentUsed: Math.round(percentUsed * 10) / 10,
      thresholdPercent: activeThreshold,
    },
  });
}

async function notifyStorageUploadBlocked({ ownerId, uploaderId, workspaceId, workspaceName }) {
  const metadata = {
    workspaceId,
    workspaceName,
    audience: 'storage_blocked',
  };

  await notifyUser({
    userId: ownerId,
    type: 'STORAGE_UPLOAD_BLOCKED',
    referenceId: `upload_blocked_${workspaceId}_${Date.now()}`,
    workspaceId,
    title: 'Storage upload blocked',
    message: workspaceName
      ? `An upload in "${workspaceName}" was blocked because storage quota is full.`
      : 'An upload was blocked because storage quota is full.',
    metadata,
  });

  if (uploaderId && uploaderId !== ownerId) {
    await notifyUser({
      userId: uploaderId,
      type: 'STORAGE_UPLOAD_BLOCKED',
      referenceId: `upload_blocked_uploader_${workspaceId}_${Date.now()}`,
      workspaceId,
      title: 'Upload blocked — storage full',
      message: 'Your upload was blocked because the workspace owner storage quota is full.',
      metadata: { ...metadata, audience: 'uploader' },
    });
  }
}

async function notifyCreditsPlatformGrant({ userId, amount, reason }) {
  return notifyUser({
    userId,
    type: 'CREDITS_PLATFORM_GRANT',
    referenceId: `grant_${userId}_${Date.now()}`,
    title: 'Credits added to your account',
    message: `${amount} AC were added to your personal balance.`,
    metadata: { amount, reason: reason || null },
  });
}

async function notifyCreditsPlatformRevoke({ userId, amount, reason }) {
  return notifyUser({
    userId,
    type: 'CREDITS_PLATFORM_REVOKE',
    referenceId: `revoke_${userId}_${Date.now()}`,
    title: 'Credits removed from your account',
    message: `${amount} AC were removed from your personal balance.`,
    metadata: { amount, reason: reason || null },
  });
}

async function notifyCreditsWorkspaceGrant({ workspaceId, workspaceName, ownerId, amount, reason }) {
  return notifyUser({
    userId: ownerId,
    type: 'CREDITS_WORKSPACE_GRANT',
    referenceId: `ws_grant_${workspaceId}_${Date.now()}`,
    workspaceId,
    title: `Credits added to ${workspaceName || 'workspace'}`,
    message: `${amount} AC were added to your team workspace pool.`,
    metadata: { workspaceId, workspaceName, amount, reason: reason || null },
  });
}

async function notifyCreditsAllocated({ ownerId, workspaceId, workspaceName, amount, direction }) {
  const type = direction === 'in' ? 'CREDITS_ALLOCATED' : 'CREDITS_DEALLOCATED';
  const title =
    direction === 'in'
      ? `Credits allocated to ${workspaceName || 'workspace'}`
      : `Credits returned from ${workspaceName || 'workspace'}`;
  const message =
    direction === 'in'
      ? `${amount} AC moved from your personal balance to the workspace pool.`
      : `${amount} AC returned from the workspace pool to your personal balance.`;

  return notifyUser({
    userId: ownerId,
    type,
    referenceId: `${type.toLowerCase()}_${workspaceId}_${Date.now()}`,
    workspaceId,
    title,
    message,
    metadata: { workspaceId, workspaceName, amount, direction },
  });
}

async function notifyStoragePlatformGrant({ userId, amountBytes, reason }) {
  const mb = Math.round(amountBytes / (1024 * 1024));
  return notifyUser({
    userId,
    type: 'STORAGE_PLATFORM_GRANT',
    referenceId: `storage_grant_${userId}_${Date.now()}`,
    title: 'Storage quota increased',
    message: `Your storage limit was increased by ${mb} MB.`,
    metadata: { amountBytes, reason: reason || null },
  });
}

async function notifyStoragePlatformRevoke({ userId, amountBytes, reason }) {
  const mb = Math.round(amountBytes / (1024 * 1024));
  return notifyUser({
    userId,
    type: 'STORAGE_PLATFORM_REVOKE',
    referenceId: `storage_revoke_${userId}_${Date.now()}`,
    title: 'Storage quota reduced',
    message: `Your storage limit was reduced by ${mb} MB.`,
    metadata: { amountBytes, reason: reason || null },
  });
}

async function notifyWorkspaceMemberJoined({ workspaceId, workspaceName, memberName, memberUserId }) {
  return notifyWorkspaceAdmins({
    workspaceId,
    excludeUserId: memberUserId,
    type: 'WORKSPACE_MEMBER_JOINED',
    referenceId: `joined_${workspaceId}_${memberUserId}`,
    title: `${memberName || 'A new member'} joined ${workspaceName}`,
    message: `${memberName || 'Someone'} accepted an invitation and joined your workspace.`,
    metadata: { workspaceId, workspaceName, memberUserId, memberName },
  });
}

async function notifyWorkspaceMemberRemoved({
  removedUserId,
  workspaceId,
  workspaceName,
  removedByAdmin,
}) {
  await notifyUser({
    userId: removedUserId,
    type: 'WORKSPACE_MEMBER_REMOVED',
    referenceId: `removed_${workspaceId}_${removedUserId}_${Date.now()}`,
    workspaceId,
    title: `Removed from ${workspaceName}`,
    message: removedByAdmin
      ? `You were removed from ${workspaceName}.`
      : `You left ${workspaceName}.`,
    metadata: { workspaceId, workspaceName, removedByAdmin },
  });

  if (removedByAdmin) {
    await notifyWorkspaceAdmins({
      workspaceId,
      excludeUserId: removedUserId,
      type: 'WORKSPACE_MEMBER_REMOVED',
      referenceId: `removed_admin_${workspaceId}_${removedUserId}_${Date.now()}`,
      title: `Member removed from ${workspaceName}`,
      message: `A member was removed from your workspace.`,
      metadata: { workspaceId, workspaceName, removedUserId },
    });
  }
}

async function notifyWorkspaceRoleChanged({
  userId,
  workspaceId,
  workspaceName,
  newRole,
  ownerId,
}) {
  await notifyUser({
    userId,
    type: 'WORKSPACE_ROLE_CHANGED',
    referenceId: `role_${workspaceId}_${userId}_${Date.now()}`,
    workspaceId,
    title: `Your role changed in ${workspaceName}`,
    message: `You are now a ${newRole} in ${workspaceName}.`,
    metadata: { workspaceId, workspaceName, newRole },
  });

  if (ownerId && ownerId !== userId) {
    await notifyUser({
      userId: ownerId,
      type: 'WORKSPACE_ROLE_CHANGED',
      referenceId: `role_owner_${workspaceId}_${userId}_${Date.now()}`,
      workspaceId,
      title: `Member role updated in ${workspaceName}`,
      message: `A member's role was changed to ${newRole}.`,
      metadata: { workspaceId, workspaceName, newRole, memberUserId: userId, audience: 'workspace_admin' },
    });
  }
}

async function notifyPlatformHeygenWalletLow({ remainingBalanceUsd, thresholdUsd }) {
  const { listPlatformSuperadminUserIds } = require('../../shared/services/platformSuperadmin.service');
  const userIds = await listPlatformSuperadminUserIds();

  return notifyMany(userIds, {
    type: 'PLATFORM_HEYGEN_WALLET_LOW',
    referenceId: 'heygen_wallet_low',
    title: 'HeyGen API wallet low',
    message: `HeyGen prepaid balance is $${remainingBalanceUsd.toFixed(2)} (below $${thresholdUsd}).`,
    metadata: {
      remainingBalanceUsd,
      thresholdUsd,
      scope: 'platform',
    },
  });
}

async function clearPlatformHeygenWalletLow() {
  const { listPlatformSuperadminUserIds } = require('../../shared/services/platformSuperadmin.service');
  const userIds = await listPlatformSuperadminUserIds();
  await Promise.all(
    userIds.map((userId) =>
      inboxDao.deleteByUserTypeReference(userId, 'PLATFORM_HEYGEN_WALLET_LOW', 'heygen_wallet_low')
    )
  );
}

function buildUnreadByCategory(unreadRows) {
  const byCategory = {
    [CATEGORIES.VIDEOS]: 0,
    [CATEGORIES.CREDITS]: 0,
    [CATEGORIES.STORAGE]: 0,
    [CATEGORIES.WORKSPACE]: 0,
    [CATEGORIES.PLATFORM]: 0,
  };

  for (const row of unreadRows) {
    const category = getCategoryForType(row.type);
    if (category && byCategory[category] !== undefined) {
      byCategory[category] += 1;
    }
  }

  return byCategory;
}

async function listInbox(userId, options = {}) {
  const { unreadOnly, limit, type, category, workspaceId } = options;
  const types = category ? getTypesForCategory(category) : undefined;

  const notifications = await inboxDao.findNotificationsByUserId(userId, {
    unreadOnly,
    limit,
    type,
    types,
    workspaceId,
  });
  const unreadCount = await inboxDao.countUnreadByUserId(userId);

  return {
    notifications: notifications.map(serializeNotification),
    unreadCount,
  };
}

async function getUnreadCount(userId) {
  const unreadCount = await inboxDao.countUnreadByUserId(userId);
  const unreadRows = await inboxDao.findUnreadNotificationsByUserId(userId);
  return {
    unreadCount,
    byCategory: buildUnreadByCategory(unreadRows),
  };
}

async function getNotification(userId, notificationId) {
  const notification = await inboxDao.findNotificationByIdForUser(notificationId, userId);
  if (!notification) {
    throw new AppError(messages.INBOX_NOTIFICATION_NOT_FOUND, 404);
  }
  return serializeNotification(notification);
}

async function markNotificationRead(userId, notificationId) {
  const notification = await inboxDao.findNotificationByIdForUser(
    notificationId,
    userId
  );
  if (!notification) {
    throw new AppError(messages.INBOX_NOTIFICATION_NOT_FOUND, 404);
  }

  if (!notification.readAt) {
    await inboxDao.markAsRead(notificationId, userId);
  }

  const updated = await inboxDao.findNotificationByIdForUser(notificationId, userId);
  return serializeNotification(updated);
}

async function markNotificationsRead(userId, notificationIds) {
  if (!notificationIds?.length) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }
  await inboxDao.markManyAsRead(userId, notificationIds);
  return { unreadCount: await inboxDao.countUnreadByUserId(userId) };
}

async function markAllNotificationsRead(userId) {
  await inboxDao.markAllAsRead(userId);
  return { unreadCount: 0 };
}

async function dismissNotification(userId, notificationId) {
  const deleted = await inboxDao.deleteNotificationForUser(notificationId, userId);
  if (deleted.count === 0) {
    throw new AppError(messages.INBOX_NOTIFICATION_NOT_FOUND, 404);
  }
  return { deleted: true };
}

module.exports = {
  notifyWorkspaceInvitation,
  syncPendingWorkspaceInvitations,
  removeInvitationNotifications,
  markInvitationNotificationRead,
  notifyUser,
  notifyMany,
  notifyWorkspaceAdmins,
  notifyVideoExportFinished,
  maybeNotifyCreditsLow,
  maybeNotifyStorageThreshold,
  notifyStorageUploadBlocked,
  notifyCreditsPlatformGrant,
  notifyCreditsPlatformRevoke,
  notifyCreditsWorkspaceGrant,
  notifyCreditsAllocated,
  notifyStoragePlatformGrant,
  notifyStoragePlatformRevoke,
  notifyWorkspaceMemberJoined,
  notifyWorkspaceMemberRemoved,
  notifyWorkspaceRoleChanged,
  notifyPlatformHeygenWalletLow,
  clearPlatformHeygenWalletLow,
  listInbox,
  getUnreadCount,
  getNotification,
  markNotificationRead,
  markNotificationsRead,
  markAllNotificationsRead,
  dismissNotification,
  getNotificationPreferences,
};
