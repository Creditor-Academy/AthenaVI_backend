const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const settingsDao = require('./settings.dao');
const {
  DEFAULT_APPEARANCE,
  INTERFACE_MODE_TO_DB,
  INTERFACE_MODE_FROM_DB,
  THEME_PALETTE_TO_DB,
  THEME_PALETTE_FROM_DB,
} = require('./appearance.constants');

const toAppearanceResponse = (record) => ({
  interfaceMode: INTERFACE_MODE_FROM_DB[record.interfaceMode],
  themePalette: THEME_PALETTE_FROM_DB[record.themePalette],
  customAccentColor: record.customAccentColor,
});

const getAppearance = async (userId) => {
  const settings = await settingsDao.findByUserId(userId);

  if (!settings) {
    return { ...DEFAULT_APPEARANCE };
  }

  return toAppearanceResponse(settings);
};

const updateAppearance = async (userId, payload) => {
  const updateData = {};

  if (payload.interfaceMode !== undefined) {
    const dbMode = INTERFACE_MODE_TO_DB[payload.interfaceMode];
    if (!dbMode) {
      throw new AppError(messages.INVALID_REQUEST, 400);
    }
    updateData.interfaceMode = dbMode;
  }

  if (payload.themePalette !== undefined) {
    const dbPalette = THEME_PALETTE_TO_DB[payload.themePalette];
    if (!dbPalette) {
      throw new AppError(messages.INVALID_REQUEST, 400);
    }
    updateData.themePalette = dbPalette;
  }

  if (payload.customAccentColor !== undefined) {
    updateData.customAccentColor = payload.customAccentColor.toUpperCase();
  }

  if (Object.keys(updateData).length === 0) {
    throw new AppError(messages.NO_VALID_FIELDS_PROVIDED, 400);
  }

  const settings = await settingsDao.upsertAppearance(userId, updateData);
  return toAppearanceResponse(settings);
};

module.exports = {
  getAppearance,
  updateAppearance,
};
