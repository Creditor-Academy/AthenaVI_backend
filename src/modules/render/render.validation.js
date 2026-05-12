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

module.exports = {
  projectRenderParamsSchema,
  createRenderSchema,
  renderByIdSchema,
};
