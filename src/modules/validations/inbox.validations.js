const Joi = require('joi');

const inboxCategories = ['videos', 'credits', 'storage', 'workspace', 'platform'];

const listInboxSchema = Joi.object({
  query: Joi.object({
    unreadOnly: Joi.string().valid('true', 'false').optional(),
    limit: Joi.number().integer().min(1).max(100).optional(),
    type: Joi.string().optional(),
    category: Joi.string().valid(...inboxCategories).optional(),
    workspaceId: Joi.string().uuid().optional(),
  }),
});

const notificationIdSchema = Joi.object({
  params: Joi.object({
    notificationId: Joi.string().uuid().required(),
  }),
});

const bulkReadSchema = Joi.object({
  body: Joi.object({
    notificationIds: Joi.array().items(Joi.string().uuid()).min(1).max(100).required(),
  })
    .unknown(false)
    .required(),
});

module.exports = {
  listInboxSchema,
  notificationIdSchema,
  bulkReadSchema,
};
