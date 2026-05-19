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
  })
    .min(1)
    .unknown(false)
    .required(),
});

module.exports = {
  updateAppearanceValidation,
  updateNotificationsValidation,
};
