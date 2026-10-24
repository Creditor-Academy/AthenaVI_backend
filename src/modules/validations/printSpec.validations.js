const Joi = require('joi');
const { PRINT_FORMAT_IDS } = require('../imageGen/catalogs/formats');

const PRINT_KINDS = Object.freeze(['poster', 'business_card', 'invitation']);

const constraintsSchema = Joi.object({
  doNotInventNumbers: Joi.boolean().default(true),
  doNotInventContactDetails: Joi.boolean().default(true),
  language: Joi.string().trim().max(16).default('en'),
  tone: Joi.string().trim().allow(null, '').optional(),
})
  .unknown(false)
  .default({ doNotInventNumbers: true, doNotInventContactDetails: true, language: 'en' });

/**
 * Server-generated PrintSpec (not the client generate body).
 * Copy and art direction are kept in full; there is no character cap.
 */
const printSpecSchema = Joi.object({
  formatId: Joi.string()
    .valid(...PRINT_FORMAT_IDS)
    .optional(),
  kind: Joi.string()
    .valid(...PRINT_KINDS)
    .optional(),
  headline: Joi.string().trim().min(1).required(),
  subheadline: Joi.string().trim().allow(null, '').optional(),
  details: Joi.array().items(Joi.string().trim().min(1)).default([]),
  cta: Joi.string().trim().allow(null, '').optional(),
  visualSubject: Joi.string().trim().min(1).required(),
  composition: Joi.string().trim().allow(null, '').optional(),
  visualStyle: Joi.string().trim().allow(null, '').optional(),
  palette: Joi.array().items(Joi.string().trim().min(1)).optional(),
  constraints: constraintsSchema,
  safeZone: Joi.string().trim().allow(null, '').optional(),
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
