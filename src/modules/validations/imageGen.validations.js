const Joi = require('joi');

/** Freeform generate/regenerate prompt. */
const IMAGE_GEN_PROMPT_MAX = 16_000;
/** Tweak follow-up instruction. */
const IMAGE_GEN_TWEAK_INSTRUCTION_MAX = 4_000;

const workspaceParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
});

const generationParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  generationId: Joi.string().uuid().required(),
});

const contextParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  contextId: Joi.string().uuid().required(),
});

const generateBody = Joi.object({
  mode: Joi.string().valid('image').default('image'),
  modelId: Joi.string().trim().max(64).allow('', null).optional(),
  formatId: Joi.string().trim().max(64).allow(null, '').optional(),
  style: Joi.string().trim().max(64).allow(null, '').optional(),
  styleId: Joi.string().trim().max(64).allow(null, '').optional(),
  prompt: Joi.string().trim().max(IMAGE_GEN_PROMPT_MAX).required(),
  brandPalette: Joi.array().items(Joi.string().trim().max(32)).max(8).optional(),
  name: Joi.string().trim().max(255).optional(),
  contextId: Joi.string().uuid().allow(null, '').optional(),
  headline: Joi.forbidden(),
  subheadline: Joi.forbidden(),
  textMode: Joi.forbidden(),
  infographic: Joi.forbidden(),
});

const generateSchema = Joi.object({
  params: workspaceParams,
  body: generateBody,
});

const regenerateSchema = Joi.object({
  params: generationParams,
  body: Joi.object({
    mode: Joi.string().valid('image').optional(),
    modelId: Joi.string().trim().max(64).optional(),
    formatId: Joi.string().trim().max(64).allow(null, '').optional(),
    style: Joi.string().trim().max(64).allow(null, '').optional(),
    styleId: Joi.string().trim().max(64).allow(null, '').optional(),
    prompt: Joi.string().trim().max(IMAGE_GEN_PROMPT_MAX).allow('', null).optional(),
    brandPalette: Joi.array().items(Joi.string().trim().max(32)).max(8).optional(),
    name: Joi.string().trim().max(255).optional(),
    contextId: Joi.string().uuid().allow(null, '').optional(),
    headline: Joi.forbidden(),
    subheadline: Joi.forbidden(),
    textMode: Joi.forbidden(),
    infographic: Joi.forbidden(),
  }).default({}),
});

const tweakSchema = Joi.object({
  params: generationParams,
  body: Joi.object({
    instruction: Joi.string().trim().min(1).max(IMAGE_GEN_TWEAK_INSTRUCTION_MAX).required(),
  }),
});

const listGenerationsSchema = Joi.object({
  params: workspaceParams,
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    mode: Joi.string().valid('image').optional(),
  }),
});

const getGenerationSchema = Joi.object({
  params: generationParams,
});

const estimateSchema = Joi.object({
  params: workspaceParams,
  query: Joi.object({
    modelId: Joi.string().trim().max(64).optional(),
    mode: Joi.string().valid('image').optional(),
    tweak: Joi.alternatives().try(Joi.boolean(), Joi.string().valid('true', 'false')).optional(),
  }),
});

const downloadSchema = Joi.object({
  params: generationParams,
  query: Joi.object({
    format: Joi.string().valid('png', 'jpg', 'jpeg', 'pdf').optional(),
  }),
});

const createContextBody = Joi.object({
  inlineText: Joi.string().trim().max(50_000).allow('', null).optional(),
  assetIds: Joi.array().items(Joi.string().uuid()).max(5).optional(),
}).default({});

const createContextSchema = Joi.object({
  params: workspaceParams,
  body: createContextBody,
});

const getContextSchema = Joi.object({
  params: contextParams,
});

const deleteContextSchema = Joi.object({
  params: contextParams,
});

module.exports = {
  IMAGE_GEN_PROMPT_MAX,
  IMAGE_GEN_TWEAK_INSTRUCTION_MAX,
  generateSchema,
  regenerateSchema,
  tweakSchema,
  listGenerationsSchema,
  getGenerationSchema,
  estimateSchema,
  downloadSchema,
  createContextSchema,
  getContextSchema,
  deleteContextSchema,
};
