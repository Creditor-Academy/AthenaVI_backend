const Joi = require('joi');
const { ARCHETYPE_IDS } = require('../imageGen/catalogs/archetypes');

const HEX_COLOR = Joi.string()
  .trim()
  .pattern(/^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/);

const sectionSchema = Joi.object({
  id: Joi.string().trim().max(64).required(),
  number: Joi.alternatives().try(Joi.number(), Joi.string().trim().max(16)).optional(),
  label: Joi.string().trim().max(200).required(),
  body: Joi.string().trim().max(800).allow('', null).optional(),
  metric: Joi.string().trim().max(80).allow('', null).optional(),
  color: HEX_COLOR.allow(null, '').optional(),
  iconHint: Joi.string().trim().max(120).allow(null, '').optional(),
  chips: Joi.array().items(Joi.string().trim().max(40)).max(8).optional(),
  emphasize: Joi.boolean().optional(),
}).unknown(false);

const flowSchema = Joi.object({
  id: Joi.string().trim().max(64).required(),
  label: Joi.string().trim().max(200).required(),
  sections: Joi.array().items(sectionSchema).min(1).max(14).required(),
}).unknown(false);

const sidebarSchema = Joi.object({
  title: Joi.string().trim().max(120).optional(),
  body: Joi.string().trim().max(600).optional(),
  items: Joi.array().items(Joi.string().trim().max(120)).max(12).optional(),
})
  .unknown(false)
  .optional();

const noteSchema = Joi.object({
  title: Joi.string().trim().max(80).optional(),
  body: Joi.string().trim().max(400).required(),
}).unknown(false);

const footerFlowSchema = Joi.object({
  items: Joi.array()
    .items(
      Joi.object({
        label: Joi.string().trim().max(80).required(),
        iconHint: Joi.string().trim().max(80).optional(),
      }).unknown(false)
    )
    .min(1)
    .max(8)
    .required(),
}).unknown(false);

const constraintsSchema = Joi.object({
  doNotInventNumbers: Joi.boolean().default(true),
  language: Joi.string().trim().max(16).default('en'),
  tone: Joi.string().trim().max(120).allow(null, '').optional(),
})
  .unknown(false)
  .default({ doNotInventNumbers: true, language: 'en' });

/**
 * Server-generated InfographicSpec (not the client generate body).
 * sections XOR flows — exactly one must be present and non-empty.
 */
const infographicSpecSchema = Joi.object({
  title: Joi.string().trim().min(1).max(200).required(),
  titleAccent: Joi.string().trim().max(80).allow(null, '').optional(),
  subtitle: Joi.string().trim().max(300).allow(null, '').optional(),
  sections: Joi.array().items(sectionSchema).max(14).optional(),
  flows: Joi.array().items(flowSchema).max(4).optional(),
  sidebar: sidebarSchema.allow(null).optional(),
  notes: Joi.array().items(noteSchema).max(4).optional(),
  footerFlow: footerFlowSchema.allow(null).optional(),
  archetype: Joi.string()
    .valid(...ARCHETYPE_IDS)
    .required(),
  orientation: Joi.string().valid('square', 'landscape', 'portrait').optional(),
  visualStyle: Joi.string().trim().max(500).allow(null, '').optional(),
  palette: Joi.array().items(HEX_COLOR).max(8).optional(),
  constraints: constraintsSchema,
})
  .unknown(false)
  .custom((value, helpers) => {
    const hasSections = Array.isArray(value.sections) && value.sections.length > 0;
    const hasFlows = Array.isArray(value.flows) && value.flows.length > 0;
    if (hasSections && hasFlows) {
      return helpers.error('any.custom', {
        message: 'Provide either sections or flows, not both',
      });
    }
    if (!hasSections && !hasFlows) {
      return helpers.error('any.custom', {
        message: 'Provide non-empty sections or flows',
      });
    }
    return value;
  }, 'sections XOR flows');

function validateInfographicSpec(spec) {
  return infographicSpecSchema.validate(spec, {
    abortEarly: false,
    stripUnknown: true,
  });
}

module.exports = {
  sectionSchema,
  flowSchema,
  infographicSpecSchema,
  validateInfographicSpec,
};
