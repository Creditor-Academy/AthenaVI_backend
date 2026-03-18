const Joi = require('joi');

const uuidParam = (name) => Joi.string().uuid().required();

const startRenderSchema = Joi.object({
  params: Joi.object({
    id: uuidParam('workspace id'),
    videoId: uuidParam('video id'),
  }),
});

const getRenderJobSchema = Joi.object({
  params: Joi.object({
    id: uuidParam('workspace id'),
    jobId: uuidParam('job id'),
  }),
});

module.exports = {
  startRenderSchema,
  getRenderJobSchema,
};
