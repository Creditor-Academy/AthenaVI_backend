const Joi = require('joi');

const workspaceGroupIdParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
    groupId: Joi.string().trim().min(1).required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspaceVoiceIdParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
    voiceId: Joi.string().trim().min(1).required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspaceHeygenListParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  workspaceGroupIdParamsSchema,
  workspaceVoiceIdParamsSchema,
  workspaceHeygenListParamsSchema,
};
