'use strict';

const Joi = require('joi');
const { deriveContentContract } = require('@athena/contracts/contentContract.js');

const columnItemSchema = Joi.object({
  title: Joi.string().allow('').optional(),
  heading: Joi.string().allow('').optional(),
  label: Joi.string().allow('').optional(),
  body: Joi.string().allow('').optional(),
  text: Joi.string().allow('').optional(),
  description: Joi.string().allow('').optional(),
}).unknown(true);

const statItemSchema = Joi.object({
  value: Joi.alternatives().try(Joi.string(), Joi.number()).optional(),
  label: Joi.string().allow('').optional(),
  name: Joi.string().allow('').optional(),
}).unknown(true);

const memberItemSchema = Joi.object({
  name: Joi.string().allow('').optional(),
  role: Joi.string().allow('').optional(),
  bio: Joi.string().allow('').optional(),
  title: Joi.string().allow('').optional(),
  body: Joi.string().allow('').optional(),
}).unknown(true);

const timelineItemSchema = Joi.object({
  label: Joi.string().allow('').optional(),
  detail: Joi.string().allow('').optional(),
  date: Joi.string().allow('').optional(),
  year: Joi.string().allow('').optional(),
  title: Joi.string().allow('').optional(),
  body: Joi.string().allow('').optional(),
  text: Joi.string().allow('').optional(),
}).unknown(true);

function arrayLengthRule(count) {
  if (!count || count <= 0) return Joi.array().optional();
  return Joi.array().max(count);
}

function buildJoiSchemaFromContract(contract) {
  const g = contract?.groups || {};
  const schema = Joi.object({
    title: Joi.string().allow('').optional(),
    subtitle: Joi.string().allow('').optional(),
    body: Joi.string().allow('').optional(),
    summary: Joi.string().allow('').optional(),
    columns: arrayLengthRule(g.columns).items(columnItemSchema).optional(),
    cards: arrayLengthRule(g.columns).items(columnItemSchema).optional(),
    features: arrayLengthRule(g.columns).items(columnItemSchema).optional(),
    stats: arrayLengthRule(g.stats).items(statItemSchema).optional(),
    members: arrayLengthRule(g.members).items(memberItemSchema).optional(),
    team: arrayLengthRule(g.members).items(memberItemSchema).optional(),
    people: arrayLengthRule(g.members).items(memberItemSchema).optional(),
    timeline: arrayLengthRule(g.timeline).items(timelineItemSchema).optional(),
    milestones: arrayLengthRule(g.timeline).items(timelineItemSchema).optional(),
    bullets: arrayLengthRule(g.bullets).items(Joi.alternatives().try(Joi.string(), Joi.object())).optional(),
    items: arrayLengthRule(g.items).items(Joi.alternatives().try(Joi.string(), Joi.object())).optional(),
    quotes: arrayLengthRule(g.quotes).items(Joi.object()).optional(),
    chart: Joi.object().unknown(true).optional(),
    diagram: Joi.object().unknown(true).optional(),
    imagePrompts: Joi.object().pattern(Joi.string(), Joi.string()).optional(),
    slotImageUrls: Joi.object().pattern(Joi.string(), Joi.string()).optional(),
  }).unknown(true);

  return schema;
}

function validateContentWithJoi(content, layoutSchema) {
  if (!layoutSchema?.slots?.length) {
    return { valid: true, errors: [] };
  }
  const contract = deriveContentContract(layoutSchema);
  const joiSchema = buildJoiSchemaFromContract(contract);
  const { error } = joiSchema.validate(content, { abortEarly: false, allowUnknown: true });
  if (!error) return { valid: true, errors: [] };
  const errors = (error.details || []).map((d) => ({
    code: 'JOI_VALIDATION',
    path: Array.isArray(d.path) ? d.path.join('.') : String(d.path || ''),
    message: d.message,
    source: 'contract',
    repairable: true,
  }));
  return { valid: false, errors };
}

module.exports = {
  buildJoiSchemaFromContract,
  validateContentWithJoi,
};
