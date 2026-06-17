const Joi = require('joi');

const workspaceProjectParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  projectId: Joi.string().uuid().required(),
});

const emptyBody = Joi.object({}).unknown(false).default({});

const createSpeechSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    sceneId: Joi.string().trim().min(1).max(256).required(),
    voiceId: Joi.string().trim().required(),
    script: Joi.string().trim().min(1).max(5000).required(),
    inputType: Joi.string().valid('text', 'ssml').optional(),
    speed: Joi.number().min(0.5).max(2).optional(),
    language: Joi.string().trim().allow(null, '').optional(),
    locale: Joi.string().trim().allow(null, '').optional(),
  }).required(),
});

const listSpeechSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

const speechIdParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  projectId: Joi.string().uuid().required(),
  speechId: Joi.string().uuid().required(),
});

const getSpeechSchema = Joi.object({
  params: speechIdParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

const downloadSpeechSchema = Joi.object({
  params: speechIdParams,
  query: Joi.object({
    expiresIn: Joi.number().integer().min(60).max(3600).optional(),
  }).unknown(false),
  body: emptyBody,
});

const getStreamSchema = Joi.object({
  params: speechIdParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

module.exports = {
  createSpeechSchema,
  listSpeechSchema,
  getSpeechSchema,
  downloadSpeechSchema,
  getStreamSchema,
};
