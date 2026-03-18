const Joi = require('joi');

const uuidParam = (name) => Joi.string().uuid().required();

const workspaceIdSchema = Joi.object({
  params: Joi.object({
    id: uuidParam('workspace id'),
  }),
});

const createVideoSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().max(255).allow('').optional(),
    aspectRatio: Joi.string().max(20).optional(),
    title: Joi.string().max(500).optional(),
    description: Joi.string().max(2000).optional(),
  }),
  params: Joi.object({
    id: uuidParam('workspace id'),
  }),
});

const videoIdSchema = Joi.object({
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
  }),
});

const updateVideoSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().max(255).optional(),
    aspectRatio: Joi.string().max(20).optional(),
    title: Joi.string().max(500).optional(),
    description: Joi.string().max(2000).optional(),
  }),
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
  }),
});

const createSceneSchema = Joi.object({
  body: Joi.object({
    order: Joi.number().integer().min(0).optional(),
    startTime: Joi.number().min(0).optional(),
    duration: Joi.number().min(0).optional(),
    payload: Joi.object().optional(),
  }),
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
  }),
});

const sceneIdSchema = Joi.object({
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
    sceneId: uuidParam('scene id'),
  }),
});

const updateSceneSchema = Joi.object({
  body: Joi.object({
    order: Joi.number().integer().min(0).optional(),
    startTime: Joi.number().min(0).optional(),
    duration: Joi.number().min(0).optional(),
    payload: Joi.object().optional(),
  }),
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
    sceneId: uuidParam('scene id'),
  }),
});

module.exports = {
  workspaceIdSchema,
  createVideoSchema,
  videoIdSchema,
  updateVideoSchema,
  createSceneSchema,
  sceneIdSchema,
  updateSceneSchema,
};
