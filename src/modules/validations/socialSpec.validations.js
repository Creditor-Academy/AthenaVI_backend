const Joi = require('joi');
const { SOCIAL_FORMAT_IDS } = require('../imageGen/catalogs/formats');

const HEX_COLOR = Joi.string()
  .trim()
  .pattern(/^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);

const constraintsSchema = Joi.object({
  doNotInventNumbers: Joi.boolean().default(true),
  language: Joi.string().trim().max(16).default('en'),
  tone: Joi.string().trim().max(120).allow(null, '').optional(),
})
  .unknown(false)
  .default({ doNotInventNumbers: true, language: 'en' });

/**
 * Server-generated SocialPostSpec (not the client generate body).
 * Global caps only; per-destination copy limits are clamped in social.service.
 */
const socialSpecSchema = Joi.object({
  formatId: Joi.string()
    .valid(...SOCIAL_FORMAT_IDS)
    .optional(),
  platform: Joi.string().trim().max(32).optional(),
  headline: Joi.string().trim().min(1).max(160).required(),
  supportingText: Joi.string().trim().max(400).allow(null, '').optional(),
  cta: Joi.string().trim().max(80).allow(null, '').optional(),
  visualSubject: Joi.string().trim().min(1).max(600).required(),
  composition: Joi.string().trim().max(600).allow(null, '').optional(),
  visualStyle: Joi.string().trim().max(500).allow(null, '').optional(),
  palette: Joi.array().items(HEX_COLOR).max(8).optional(),
  constraints: constraintsSchema,
  safeZone: Joi.string().trim().max(600).allow(null, '').optional(),
}).unknown(false);

function validateSocialSpec(spec) {
  return socialSpecSchema.validate(spec, {
    abortEarly: false,
    stripUnknown: true,
  });
}

module.exports = {
  socialSpecSchema,
  validateSocialSpec,
};
