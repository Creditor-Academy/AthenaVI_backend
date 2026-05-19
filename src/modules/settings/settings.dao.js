const prisma = require('../../shared/config/prismaClient');
const { DEFAULT_APPEARANCE } = require('./appearance.constants');

const defaultCreateData = {
  interfaceMode: 'LIGHT',
  themePalette: 'SAPPHIRE',
  customAccentColor: DEFAULT_APPEARANCE.customAccentColor,
};

const findByUserId = async (userId) => {
  return prisma.userSettings.findUnique({
    where: { userId },
  });
};

const upsertAppearance = async (userId, data) => {
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
  upsertAppearance,
};
