const Joi = require('joi');

const searchStockSchema = Joi.object({
  query: Joi.object({
    q: Joi.string().trim().min(1).max(200).required(),
    type: Joi.string().valid('photo', 'video').default('photo'),
    page: Joi.number().integer().min(1).max(100).default(1),
    perPage: Joi.number().integer().min(1).max(80).default(20),
  }),
});

const importStockSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  body: Joi.object({
    provider: Joi.string().valid('pexels').required(),
    externalId: Joi.string().trim().min(1).max(64).required(),
    mediaType: Joi.string().valid('photo', 'video').required(),
    name: Joi.string().trim().min(1).max(255).optional(),
  }),
});

module.exports = {
  searchStockSchema,
  importStockSchema,
};
