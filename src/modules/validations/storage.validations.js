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

const storageUpgradeRequestBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    requestedAdditionalGb: Joi.number().positive().required(),
    requestedAdditionalBytes: Joi.number().integer().positive().required(),
    reason: Joi.string().trim().min(10).max(2000).required(),
    urgency: Joi.string().valid('flexible', 'week', 'urgent').required(),
    currentUsedBytes: Joi.number().integer().min(0).required(),
    currentLimitBytes: Joi.number().integer().min(0).required(),
    tierId: Joi.string().trim().max(64).allow(null),
    tierLabel: Joi.string().trim().max(128).allow(null),
    workspaceId: Joi.string().uuid().allow(null),
    workspaceName: Joi.string().trim().max(256).allow(null),
    workspaceFootprintBytes: Joi.number().integer().min(0).allow(null),
  })
    .unknown(false)
    .required(),
});

const storageUpgradeRequestsQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    status: Joi.string().valid('pending', 'approved', 'rejected').optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  storageSummarySchema,
  storageHistoryQuerySchema,
  workspaceStorageParamsSchema,
  storageUpgradeRequestBodySchema,
  storageUpgradeRequestsQuerySchema,
};
