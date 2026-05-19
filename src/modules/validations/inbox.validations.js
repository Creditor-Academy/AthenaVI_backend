const Joi = require('joi');

const listInboxSchema = Joi.object({
  query: Joi.object({
    unreadOnly: Joi.string().valid('true', 'false').optional(),
    limit: Joi.number().integer().min(1).max(100).optional(),
  }),
});

const notificationIdSchema = Joi.object({
  params: Joi.object({
    notificationId: Joi.string().uuid().required(),
  }),
});

module.exports = {
  listInboxSchema,
  notificationIdSchema,
};
