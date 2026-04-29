const Joi = require('joi');

const generateAvatarVideoSchema = Joi.object({
  body: Joi.object({
    avatarId: Joi.string().trim().required(),
    title: Joi.string().trim().required(),
    resolution: Joi.string().trim().required(),
    aspectRatio: Joi.string().trim().required(),
    backgroundColor: Joi.string().trim().required(),
    voiceId: Joi.string().trim().required(),
    script: Joi.string().trim().required(),
    expressiveness: Joi.string().trim().required(),
    workspaceId: Joi.string().uuid().required(),
    projectId: Joi.string().uuid().required(),
  }).required(),
  params: Joi.object().optional(),
  query: Joi.object().optional(),
});

module.exports = {
  generateAvatarVideoSchema,
};
