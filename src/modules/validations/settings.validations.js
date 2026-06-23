const Joi = require('joi');

const hexColorSchema = Joi.string()
  .pattern(/^#[0-9A-Fa-f]{6}$/)
  .messages({
    'string.pattern.base': 'customAccentColor must be a 6-digit hex color (e.g. #2563EB)',
  });

const updateAppearanceValidation = Joi.object({
  body: Joi.object({
    interfaceMode: Joi.string().valid('light', 'dark'),
    themePalette: Joi.string().valid(
      'original',
      'sapphire',
      'ocean',
      'forest',
      'sunset',
      'custom'
    ),
    customAccentColor: hexColorSchema,
  })
    .min(1)
    .unknown(false)
    .required(),
});

const updateNotificationsValidation = Joi.object({
  body: Joi.object({
    pushNotifications: Joi.boolean(),
    commentsAndMentions: Joi.boolean(),
    weeklyDigestEmail: Joi.boolean(),
    productEmails: Joi.boolean(),
    videoExportAlerts: Joi.boolean(),
    workspaceVideoExportAlerts: Joi.boolean(),
    creditsAlerts: Joi.boolean(),
    storageAlerts: Joi.boolean(),
    workspaceTeamAlerts: Joi.boolean(),
    platformAdminAlerts: Joi.boolean(),
  })
    .min(1)
    .unknown(false)
    .required(),
});

const changePasswordValidation = Joi.object({
  body: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
  })
    .unknown(false)
    .required(),
});

const deleteAccountValidation = Joi.object({
  body: Joi.object({
    confirmation: Joi.string().valid('delete').required().messages({
      'any.only': 'Type delete to confirm account deletion',
    }),
  })
    .unknown(false)
    .required(),
});

module.exports = {
  updateAppearanceValidation,
  updateNotificationsValidation,
  changePasswordValidation,
  deleteAccountValidation,
};
