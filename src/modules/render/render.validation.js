const Joi = require('joi');

const uuidParam = Joi.string().uuid().required();

const projectRenderParamsSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
});

const createRenderSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
  body: Joi.object({
    forceRebuild: Joi.boolean().default(false),
  }).default({}),
});

const renderByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
    renderId: uuidParam,
  }),
});

const workspaceVideosSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    status: Joi.string().valid('queued', 'processing', 'completed', 'failed').optional(),
  }).unknown(false),
});

const ownerVideosSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    status: Joi.string().valid('queued', 'processing', 'completed', 'failed').optional(),
  }).unknown(false),
});

module.exports = {
  projectRenderParamsSchema,
  createRenderSchema,
  renderByIdSchema,
  workspaceVideosSchema,
  ownerVideosSchema,
};
