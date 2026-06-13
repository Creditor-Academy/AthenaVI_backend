const Joi = require('joi');
const { FEATURE, HEYGEN_AVATAR_TYPES } = require('../../shared/config/creditPricing');
const { HEYGEN_AVATAR_ENGINE_VALUES } = require('../../shared/constants/heygen');

const HEYGEN_AVATAR_TYPE_VALUES = Object.freeze([
  HEYGEN_AVATAR_TYPES.PHOTO,
  HEYGEN_AVATAR_TYPES.STUDIO,
  HEYGEN_AVATAR_TYPES.DIGITAL_TWIN,
]);

const workspaceIdParamSchema = Joi.object({
  params: Joi.object({
    id: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const allocateBodySchema = Joi.object({
  params: Joi.object({
    id: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    amount: Joi.number().integer().min(1).required(),
  }).required(),
});

const paginationQuerySchema = Joi.object({
  params: Joi.object({
    id: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspaceEstimateQuerySchema = Joi.object({
  params: Joi.object({
    id: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    feature: Joi.string()
      .valid(FEATURE.HEYGEN_VIDEO, FEATURE.REMOTION_EXPORT)
      .required(),
    avatarEngine: Joi.string()
      .valid(...HEYGEN_AVATAR_ENGINE_VALUES)
      .when('feature', { is: FEATURE.HEYGEN_VIDEO, then: Joi.optional(), otherwise: Joi.forbidden() }),
    avatarType: Joi.string()
      .valid(...HEYGEN_AVATAR_TYPE_VALUES)
      .when('feature', { is: FEATURE.HEYGEN_VIDEO, then: Joi.optional(), otherwise: Joi.forbidden() }),
    resolution: Joi.string()
      .trim()
      .valid('720p', '1080p')
      .when('feature', { is: FEATURE.HEYGEN_VIDEO, then: Joi.optional(), otherwise: Joi.forbidden() }),
    script: Joi.string().trim().optional(),
    durationInFrames: Joi.number().integer().min(1).optional(),
    fps: Joi.number().min(1).max(120).optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

const personalEstimateQuerySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    feature: Joi.string()
      .valid(
        FEATURE.VOICE_CLONE,
        FEATURE.VOICE_DESIGN,
        FEATURE.VOICE_PREVIEW,
        FEATURE.AVATAR_CREATE
      )
      .required(),
    text: Joi.string().trim().optional(),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  workspaceIdParamSchema,
  allocateBodySchema,
  paginationQuerySchema,
  workspaceEstimateQuerySchema,
  personalEstimateQuerySchema,
};
