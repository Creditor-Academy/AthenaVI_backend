const prisma = require('../../shared/config/prismaClient');

const createNotification = async (data) => {
  return await prisma.userInboxNotification.create({ data });
};

const upsertNotification = async ({
  userId,
  type,
  referenceId,
  workspaceId,
  title,
  message,
  metadata,
  invitationId,
}) => {
  if (!referenceId) {
    return await createNotification({
      userId,
      type,
      workspaceId: workspaceId || null,
      title,
      message,
      metadata,
      invitationId: invitationId || null,
      referenceId: null,
    });
  }

  return await prisma.userInboxNotification.upsert({
    where: {
      userId_type_referenceId: {
        userId,
        type,
        referenceId,
      },
    },
    create: {
      userId,
      type,
      referenceId,
      workspaceId: workspaceId || null,
      title,
      message,
      metadata,
      invitationId: invitationId || null,
    },
    update: {
      title,
      message,
      metadata,
      workspaceId: workspaceId || null,
      readAt: null,
    },
  });
};

const upsertWorkspaceInvitationNotification = async (data) => {
  const { userId, invitationId, workspaceId, ...rest } = data;
  return await prisma.userInboxNotification.upsert({
    where: {
      userId_invitationId: { userId, invitationId },
    },
    create: {
      userId,
      invitationId,
      referenceId: invitationId,
      workspaceId: workspaceId || null,
      ...rest,
    },
    update: {
      title: rest.title,
      message: rest.message,
      metadata: rest.metadata,
      workspaceId: workspaceId || null,
      referenceId: invitationId,
      readAt: null,
    },
  });
};

const findNotificationsByUserId = async (
  userId,
  { unreadOnly = false, limit = 50, type, types, workspaceId } = {}
) => {
  const typeFilter = types?.length ? { in: types } : type ? type : undefined;

  return await prisma.userInboxNotification.findMany({
    where: {
      userId,
      ...(unreadOnly ? { readAt: null } : {}),
      ...(typeFilter ? { type: typeFilter } : {}),
      ...(workspaceId ? { workspaceId } : {}),
    },
    orderBy: { createdAt: 'desc' },
    take: limit,
  });
};

const countUnreadByUserId = async (userId) => {
  return await prisma.userInboxNotification.count({
    where: { userId, readAt: null },
  });
};

const findUnreadNotificationsByUserId = async (userId) => {
  return await prisma.userInboxNotification.findMany({
    where: { userId, readAt: null },
    select: { type: true },
  });
};

const findNotificationByIdForUser = async (notificationId, userId) => {
  return await prisma.userInboxNotification.findFirst({
    where: { id: notificationId, userId },
  });
};

const markAsRead = async (notificationId, userId) => {
  return await prisma.userInboxNotification.updateMany({
    where: { id: notificationId, userId, readAt: null },
    data: { readAt: new Date() },
  });
};

const markManyAsRead = async (userId, notificationIds) => {
  return await prisma.userInboxNotification.updateMany({
    where: {
      userId,
      id: { in: notificationIds },
      readAt: null,
    },
    data: { readAt: new Date() },
  });
};

const markAllAsRead = async (userId) => {
  return await prisma.userInboxNotification.updateMany({
    where: { userId, readAt: null },
    data: { readAt: new Date() },
  });
};

const deleteNotificationForUser = async (notificationId, userId) => {
  return await prisma.userInboxNotification.deleteMany({
    where: { id: notificationId, userId },
  });
};

const deleteByInvitationId = async (invitationId) => {
  return await prisma.userInboxNotification.deleteMany({
    where: { invitationId },
  });
};

const deleteByUserTypeReference = async (userId, type, referenceId) => {
  return await prisma.userInboxNotification.deleteMany({
    where: { userId, type, referenceId },
  });
};

const markReadByInvitationForUser = async (userId, invitationId) => {
  return await prisma.userInboxNotification.updateMany({
    where: { userId, invitationId, readAt: null },
    data: { readAt: new Date() },
  });
};

const findPendingInvitationsByEmail = async (email) => {
  return await prisma.invitation.findMany({
    where: {
      email,
      status: 'PENDING',
      expiresAt: { gt: new Date() },
    },
    include: {
      workspace: { select: { id: true, name: true } },
    },
  });
};

const findWorkspaceAdminsAndOwners = async (workspaceId) => {
  return await prisma.workspaceMember.findMany({
    where: {
      workspaceId,
      role: { in: ['OWNER', 'ADMIN'] },
    },
    include: {
      user: { select: { id: true, name: true, email: true } },
    },
  });
};

const countUnreadPlatformByUserId = async (userId) => {
  return await prisma.userInboxNotification.count({
    where: {
      userId,
      readAt: null,
      type: 'PLATFORM_HEYGEN_WALLET_LOW',
    },
  });
};

module.exports = {
  createNotification,
  upsertNotification,
  upsertWorkspaceInvitationNotification,
  findNotificationsByUserId,
  countUnreadByUserId,
  findUnreadNotificationsByUserId,
  findNotificationByIdForUser,
  markAsRead,
  markManyAsRead,
  markAllAsRead,
  deleteNotificationForUser,
  deleteByInvitationId,
  deleteByUserTypeReference,
  markReadByInvitationForUser,
  findPendingInvitationsByEmail,
  findWorkspaceAdminsAndOwners,
  countUnreadPlatformByUserId,
};
