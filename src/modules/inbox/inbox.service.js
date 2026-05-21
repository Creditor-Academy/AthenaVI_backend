const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const inboxDao = require('./inbox.dao');

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

async function notifyWorkspaceInvitation({ userId, invitation, workspace, inviter }) {
  if (!invitation?.id || !workspace) return null;

  const payload = formatWorkspaceInvitationNotification({
    invitation,
    workspace,
    inviter,
  });

  return await inboxDao.upsertWorkspaceInvitationNotification({
    userId,
    invitationId: invitation.id,
    ...payload,
  });
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

async function listInbox(userId, options = {}) {
  const notifications = await inboxDao.findNotificationsByUserId(userId, options);
  const unreadCount = await inboxDao.countUnreadByUserId(userId);

  return { notifications, unreadCount };
}

async function getUnreadCount(userId) {
  const unreadCount = await inboxDao.countUnreadByUserId(userId);
  return { unreadCount };
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

  return await inboxDao.findNotificationByIdForUser(notificationId, userId);
}

async function markAllNotificationsRead(userId) {
  await inboxDao.markAllAsRead(userId);
  return { unreadCount: 0 };
}

module.exports = {
  notifyWorkspaceInvitation,
  syncPendingWorkspaceInvitations,
  removeInvitationNotifications,
  markInvitationNotificationRead,
  listInbox,
  getUnreadCount,
  markNotificationRead,
  markAllNotificationsRead,
};
