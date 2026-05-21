const prisma = require('../../shared/config/prismaClient');

const createNotification = async (data) => {
  return await prisma.userInboxNotification.create({ data });
};

const upsertWorkspaceInvitationNotification = async (data) => {
  const { userId, invitationId, ...rest } = data;
  return await prisma.userInboxNotification.upsert({
    where: {
      userId_invitationId: { userId, invitationId },
    },
    create: { userId, invitationId, ...rest },
    update: {
      title: rest.title,
      message: rest.message,
      metadata: rest.metadata,
      readAt: null,
    },
  });
};

const findNotificationsByUserId = async (userId, { unreadOnly = false, limit = 50 } = {}) => {
  return await prisma.userInboxNotification.findMany({
    where: {
      userId,
      ...(unreadOnly ? { readAt: null } : {}),
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

const markAllAsRead = async (userId) => {
  return await prisma.userInboxNotification.updateMany({
    where: { userId, readAt: null },
    data: { readAt: new Date() },
  });
};

const deleteByInvitationId = async (invitationId) => {
  return await prisma.userInboxNotification.deleteMany({
    where: { invitationId },
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

module.exports = {
  createNotification,
  upsertWorkspaceInvitationNotification,
  findNotificationsByUserId,
  countUnreadByUserId,
  findNotificationByIdForUser,
  markAsRead,
  markAllAsRead,
  deleteByInvitationId,
  markReadByInvitationForUser,
  findPendingInvitationsByEmail,
};
