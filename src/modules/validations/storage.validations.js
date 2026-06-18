const Joi = require('joi');

const storageSummarySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const storageHistoryQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    type: Joi.string().trim().max(64).optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspaceStorageParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  storageSummarySchema,
  storageHistoryQuerySchema,
  workspaceStorageParamsSchema,
};
