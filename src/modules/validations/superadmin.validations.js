const Joi = require('joi');

const userIdParamsSchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspaceIdParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const grantRevokeBodySchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    amount: Joi.number().integer().min(1).required(),
    reason: Joi.string().trim().max(500).optional(),
  }).required(),
});

const grantRevokeWorkspaceBodySchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    amount: Joi.number().integer().min(1).required(),
    reason: Joi.string().trim().max(500).optional(),
  }).required(),
});

const listUsersQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    search: Joi.string().trim().max(255).optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const historyQuerySchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    type: Joi.string().trim().max(64).optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const usageReportQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    from: Joi.date().iso().optional(),
    to: Joi.date().iso().optional(),
    workspaceId: Joi.string().uuid().optional(),
    userId: Joi.string().uuid().optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  userIdParamsSchema,
  workspaceIdParamsSchema,
  grantRevokeBodySchema,
  grantRevokeWorkspaceBodySchema,
  listUsersQuerySchema,
  historyQuerySchema,
  usageReportQuerySchema,
};
