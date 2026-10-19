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

const createUserBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    // Same constraints as self-service register so admin-created accounts look identical.
    name: Joi.string().trim().min(2).max(50).required(),
    email: Joi.string().trim().lowercase().email().max(254).required(),
    // Optional: when omitted the user gets a "set your password" email instead.
    password: Joi.string()
      .min(8)
      .max(128)
      .custom((value, helpers) =>
        Buffer.byteLength(value, 'utf8') > 72 ? helpers.error('string.max', { limit: 72 }) : value
      )
      .allow('', null)
      .optional(),
    sendWelcomeEmail: Joi.boolean().default(true),
  })
    .custom((value, helpers) => {
      const hasPassword = typeof value.password === 'string' && value.password !== '';
      return hasPassword || value.sendWelcomeEmail
        ? value
        : helpers.message('Provide a password or enable the welcome email');
    })
    .required(),
});

const pauseUserBodySchema = Joi.object({
  params: Joi.object({ userId: Joi.string().uuid().required() }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    reason: Joi.string().trim().max(500).allow('', null).optional(),
  }).default({}),
});

const deleteUserBodySchema = Joi.object({
  params: Joi.object({ userId: Joi.string().uuid().required() }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    // Typed confirmation: must equal the target user's email (checked in the service).
    confirmEmail: Joi.string().trim().lowercase().email().max(254).required(),
  }).required(),
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

const broadcastIdParamsSchema = Joi.object({
  params: Joi.object({
    broadcastId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const productEmailBroadcastHistoryQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const productEmailBroadcastRecipientsQuerySchema = Joi.object({
  params: Joi.object({
    broadcastId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(50),
    status: Joi.string().valid('SENT', 'FAILED').optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const createEmailTemplateBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(100).required(),
    subject: Joi.string().trim().max(200).allow('').default(''),
    htmlBody: Joi.string().trim().min(1).required(),
    textBody: Joi.string().trim().allow(null, '').optional(),
    type: Joi.string().valid('html', 'design', 'text').default('html'),
  }).required(),
});

const updateEmailTemplateBodySchema = Joi.object({
  params: Joi.object({
    templateId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(100).optional(),
    subject: Joi.string().trim().max(200).allow('').optional(),
    htmlBody: Joi.string().trim().min(1).optional(),
    textBody: Joi.string().trim().allow(null, '').optional(),
    type: Joi.string().valid('html', 'design', 'text').optional(),
  }).min(1).required(),
});

const emailTemplateIdParamsSchema = Joi.object({
  params: Joi.object({
    templateId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const listEmailTemplatesQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(50),
    search: Joi.string().trim().optional(),
    type: Joi.string().valid('html', 'design', 'text').optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const resendProductEmailBroadcastBodySchema = Joi.object({
  params: Joi.object({
    broadcastId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    emails: Joi.array().items(Joi.string().email().trim()).min(1).optional(),
    confirm: Joi.string().valid('send').required().messages({
      'any.only': 'Type send to confirm product email broadcast resend',
    }),
  }).required(),
});

module.exports = {
  createUserBodySchema,
  pauseUserBodySchema,
  deleteUserBodySchema,
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
  broadcastIdParamsSchema,
  productEmailBroadcastHistoryQuerySchema,
  productEmailBroadcastRecipientsQuerySchema,
  createEmailTemplateBodySchema,
  updateEmailTemplateBodySchema,
  emailTemplateIdParamsSchema,
  listEmailTemplatesQuerySchema,
  resendProductEmailBroadcastBodySchema,
};
