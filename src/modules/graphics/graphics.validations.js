const Joi = require('joi');

const GRAPHIC_TYPES = ['decorative', 'illustration', 'icon', 'abstract', 'pattern'];
const COLOR_MODES = ['recolorable', 'fixed'];
const STATUSES = ['draft', 'published', 'archived'];

const csvOrArray = Joi.alternatives().try(
  Joi.array().items(Joi.string().trim().max(48)).max(24),
  Joi.string().allow('')
);

const metadataBody = {
  name: Joi.string().trim().min(1).max(120),
  description: Joi.string().trim().max(2000).allow('', null),
  type: Joi.string().valid(...GRAPHIC_TYPES),
  category: Joi.string().trim().min(1).max(64),
  tags: csvOrArray,
  style: Joi.string().trim().max(64).allow('', null),
  moods: csvOrArray,
  usage: csvOrArray,
  colorMode: Joi.string().valid(...COLOR_MODES),
  containsText: Joi.alternatives().try(Joi.boolean(), Joi.string().valid('true', 'false', '1', '0')),
};

const idParams = Joi.object({
  params: Joi.object({ id: Joi.string().trim().required() }),
  body: Joi.object().optional(),
  query: Joi.object().optional(),
});

const createGraphicSchema = Joi.object({
  params: Joi.object().optional(),
  query: Joi.object().optional(),
  body: Joi.object({
    ...metadataBody,
    name: metadataBody.name.optional(),
    type: metadataBody.type.default('decorative'),
    category: metadataBody.category.default('ornaments'),
    colorMode: metadataBody.colorMode.default('recolorable'),
  }),
});

const updateGraphicSchema = Joi.object({
  params: Joi.object({ id: Joi.string().trim().required() }),
  query: Joi.object().optional(),
  body: Joi.object(metadataBody),
});

const listGraphicsQuerySchema = Joi.object({
  params: Joi.object().optional(),
  body: Joi.object().optional(),
  query: Joi.object({
    q: Joi.string().trim().allow('').optional(),
    category: Joi.string().trim().optional(),
    type: Joi.string().valid(...GRAPHIC_TYPES).optional(),
    style: Joi.string().trim().optional(),
    mood: Joi.string().trim().optional(),
    colorMode: Joi.string().valid(...COLOR_MODES).optional(),
    status: Joi.string().valid(...STATUSES).optional(),
    page: Joi.number().integer().min(1).optional(),
    limit: Joi.number().integer().min(1).max(100).optional(),
  }),
});

const searchIntentSchema = Joi.object({
  params: Joi.object().optional(),
  query: Joi.object().optional(),
  body: Joi.object({
    keywords: Joi.array().items(Joi.string().trim().max(48)).max(24).default([]),
    style: Joi.string().trim().max(64).allow('', null).optional(),
    mood: Joi.string().trim().max(64).allow('', null).optional(),
    preferredType: Joi.string().valid(...GRAPHIC_TYPES).optional(),
    usage: Joi.string().trim().max(64).allow('', null).optional(),
    maxCount: Joi.number().integer().min(1).max(8).optional(),
  }),
});

const getIllustrationsFreeQuerySchema = Joi.object({
  params: Joi.object().optional(),
  body: Joi.object().optional(),
  query: Joi.object({
    kind: Joi.string().valid('illustration', 'icon').default('illustration'),
    categoryId: Joi.string().trim().allow('').optional(),
    packId: Joi.string().trim().allow('').optional(),
    q: Joi.string().trim().allow('').optional(),
    page: Joi.number().integer().min(1).optional(),
    limit: Joi.number().integer().min(1).max(100).optional(),
  }),
});

const importGetIllustrationsIconPackSchema = Joi.object({
  params: Joi.object({
    packId: Joi.string().trim().required(),
  }),
  query: Joi.object().optional(),
  body: Joi.object({
    publishAssets: Joi.boolean().optional(),
  }).optional(),
});

module.exports = {
  GRAPHIC_TYPES,
  COLOR_MODES,
  STATUSES,
  idParams,
  createGraphicSchema,
  updateGraphicSchema,
  listGraphicsQuerySchema,
  searchIntentSchema,
  getIllustrationsFreeQuerySchema,
  importGetIllustrationsIconPackSchema,
};
