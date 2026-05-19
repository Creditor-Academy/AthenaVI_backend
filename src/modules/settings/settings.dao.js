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

module.exports = {
  findByUserId,
  upsertSettings,
};
