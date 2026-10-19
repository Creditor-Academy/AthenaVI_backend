const Joi = require('joi');
const { PRINT_FORMAT_IDS } = require('../imageGen/catalogs/formats');

const HEX_COLOR = Joi.string()
  .trim()
  .pattern(/^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);

const PRINT_KINDS = Object.freeze(['poster', 'business_card', 'invitation']);

const constraintsSchema = Joi.object({
  doNotInventNumbers: Joi.boolean().default(true),
  doNotInventContactDetails: Joi.boolean().default(true),
  language: Joi.string().trim().max(16).default('en'),
  tone: Joi.string().trim().max(120).allow(null, '').optional(),
})
  .unknown(false)
  .default({ doNotInventNumbers: true, doNotInventContactDetails: true, language: 'en' });

/**
 * Server-generated PrintSpec (not the client generate body).
 * Global caps only; per-size copy limits are clamped in print.service.
 */
const printSpecSchema = Joi.object({
  formatId: Joi.string()
    .valid(...PRINT_FORMAT_IDS)
    .optional(),
  kind: Joi.string()
    .valid(...PRINT_KINDS)
    .optional(),
  headline: Joi.string().trim().min(1).max(160).required(),
  subheadline: Joi.string().trim().max(300).allow(null, '').optional(),
  details: Joi.array().items(Joi.string().trim().min(1).max(160)).max(8).default([]),
  cta: Joi.string().trim().max(80).allow(null, '').optional(),
  visualSubject: Joi.string().trim().min(1).max(600).required(),
  composition: Joi.string().trim().max(600).allow(null, '').optional(),
  visualStyle: Joi.string().trim().max(500).allow(null, '').optional(),
  palette: Joi.array().items(HEX_COLOR).max(8).optional(),
  constraints: constraintsSchema,
  safeZone: Joi.string().trim().max(600).allow(null, '').optional(),
}).unknown(false);

function validatePrintSpec(spec) {
  return printSpecSchema.validate(spec, {
    abortEarly: false,
    stripUnknown: true,
  });
}

module.exports = {
  PRINT_KINDS,
  printSpecSchema,
  validatePrintSpec,
};
