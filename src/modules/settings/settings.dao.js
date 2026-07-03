const prisma = require('../../shared/config/prismaClient');
const { DEFAULT_APPEARANCE } = require('./appearance.constants');
const { DEFAULT_NOTIFICATIONS } = require('./notifications.constants');

const defaultCreateData = {
  interfaceMode: 'LIGHT',
  themePalette: 'SAPPHIRE',
  customAccentColor: DEFAULT_APPEARANCE.customAccentColor,
  pushNotifications: DEFAULT_NOTIFICATIONS.pushNotifications,
  commentsAndMentions: DEFAULT_NOTIFICATIONS.commentsAndMentions,
  weeklyDigestEmail: DEFAULT_NOTIFICATIONS.weeklyDigestEmail,
  productEmails: DEFAULT_NOTIFICATIONS.productEmails,
  videoExportAlerts: DEFAULT_NOTIFICATIONS.videoExportAlerts,
  workspaceVideoExportAlerts: DEFAULT_NOTIFICATIONS.workspaceVideoExportAlerts,
  creditsAlerts: DEFAULT_NOTIFICATIONS.creditsAlerts,
  storageAlerts: DEFAULT_NOTIFICATIONS.storageAlerts,
  workspaceTeamAlerts: DEFAULT_NOTIFICATIONS.workspaceTeamAlerts,
  platformAdminAlerts: DEFAULT_NOTIFICATIONS.platformAdminAlerts,
};

const findByUserId = async (userId) => {
  return prisma.userSettings.findUnique({
    where: { userId },
  });
};

const upsertSettings = async (userId, data) => {
  return prisma.userSettings.upsert({
    where: { userId },
    create: {
      userId,
      ...defaultCreateData,
      ...data,
    },
    update: data,
  });
};

const findUsersWithNotificationPreference = async (prefKey) => {
  const allowedKeys = ['weeklyDigestEmail', 'productEmails'];
  if (!allowedKeys.includes(prefKey)) {
    throw new Error(`Invalid notification preference key: ${prefKey}`);
  }

  return prisma.user.findMany({
    where: {
      email: { not: null },
      deletionScheduledAt: null,
      settings: {
        [prefKey]: true,
      },
    },
    select: {
      id: true,
      email: true,
      name: true,
      settings: {
        select: {
          lastWeeklyDigestSentAt: true,
        },
      },
    },
  });
};

const updateLastWeeklyDigestSentAt = async (userId, sentAt = new Date()) => {
  return upsertSettings(userId, { lastWeeklyDigestSentAt: sentAt });
};

module.exports = {
  findByUserId,
  upsertSettings,
  findUsersWithNotificationPreference,
  updateLastWeeklyDigestSentAt,
};
