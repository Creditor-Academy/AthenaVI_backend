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

const requestIdParamsSchema = Joi.object({
  params: Joi.object({
    requestId: Joi.string().uuid().required(),
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

const grantStorageBodySchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    additionalBytes: Joi.number().integer().min(1).optional(),
    tierId: Joi.string().trim().max(64).optional(),
    reason: Joi.string().trim().max(500).optional(),
  })
    .or('additionalBytes', 'tierId')
    .required(),
});

const revokeStorageBodySchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    amountBytes: Joi.number().integer().min(1).required(),
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

const listWorkspacesQuerySchema = Joi.object({
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

const workspaceHistoryQuerySchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    type: Joi.string().trim().max(64).optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspacePaginationQuerySchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const storageHistoryQuerySchema = Joi.object({
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

const storageRequestsQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    status: Joi.string().valid('pending', 'approved', 'rejected').optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const rejectStorageRequestBodySchema = Joi.object({
  params: Joi.object({
    requestId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    reviewNote: Joi.string().trim().max(500).optional(),
  }).default({}),
});

const usageReportQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    from: Joi.date().iso().optional(),
    to: Joi.date().iso().optional(),
    workspaceId: Joi.string().uuid().optional(),
    userId: Joi.string().uuid().optional(),
    topLimit: Joi.number().integer().min(1).max(25).default(10),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const platformActionsQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    from: Joi.date().iso().optional(),
    to: Joi.date().iso().optional(),
    type: Joi.string().valid('platform_grant', 'platform_revoke').optional(),
    scope: Joi.string().valid('user', 'workspace').optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const platformAccessBodySchema = Joi.object({
  params: Joi.object({
    userId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    isPlatformSuperadmin: Joi.boolean().required(),
  }).required(),
});

const productEmailBroadcastBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    subject: Joi.string().trim().min(3).max(200).required(),
    html: Joi.string().trim().min(10).required(),
    text: Joi.string().trim().optional(),
    confirm: Joi.string().valid('send').required().messages({
      'any.only': 'Type send to confirm product email broadcast',
    }),
  }).required(),
});

module.exports = {
  userIdParamsSchema,
  workspaceIdParamsSchema,
  requestIdParamsSchema,
  grantRevokeBodySchema,
  grantStorageBodySchema,
  revokeStorageBodySchema,
  grantRevokeWorkspaceBodySchema,
  listUsersQuerySchema,
  listWorkspacesQuerySchema,
  historyQuerySchema,
  workspaceHistoryQuerySchema,
  workspacePaginationQuerySchema,
  storageHistoryQuerySchema,
  storageRequestsQuerySchema,
  rejectStorageRequestBodySchema,
  usageReportQuerySchema,
  platformActionsQuerySchema,
  platformAccessBodySchema,
  productEmailBroadcastBodySchema,
};
