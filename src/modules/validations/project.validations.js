const Joi = require('joi');

const createProjectSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  body: Joi.object({
    name: Joi.string().min(1).max(255).required(),
    folderId: Joi.string().uuid().required(),
    projectState: Joi.any().default({}),
    data: Joi.any().default({}),
    thumbnail: Joi.string().uri().optional(),
    duration: Joi.number().integer().min(0).optional(),
    status: Joi.string().valid('draft', 'rendering', 'completed').optional(),
  }),
});

module.exports = {
  createProjectSchema,
};
