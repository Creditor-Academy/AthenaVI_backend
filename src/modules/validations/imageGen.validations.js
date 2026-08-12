const Joi = require('joi');

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

const infographicSchema = Joi.object({
  layout: Joi.string()
    .valid('process', 'comparison', 'timeline', 'stats', 'hierarchy', 'funnel', 'custom')
    .optional(),
  title: Joi.string().trim().max(200).allow('', null).optional(),
  sections: Joi.array()
    .items(
      Joi.object({
        title: Joi.string().trim().max(200).allow('', null).optional(),
        bullets: Joi.array().items(Joi.string().trim().max(500)).max(20).optional(),
        content: Joi.string().trim().max(2000).allow('', null).optional(),
      })
    )
    .max(12)
    .optional(),
}).unknown(true);

const generateBody = Joi.object({
  mode: Joi.string().valid('image', 'infographic', 'social').default('image'),
  modelId: Joi.string().trim().max(64).default('gpt-image-1'),
  formatId: Joi.string().trim().max(64).allow(null, '').optional(),
  style: Joi.string().trim().max(64).allow(null, '').optional(),
  styleId: Joi.string().trim().max(64).allow(null, '').optional(),
  prompt: Joi.string().trim().max(4000).allow('', null).optional(),
  headline: Joi.string().trim().max(200).allow('', null).optional(),
  subheadline: Joi.string().trim().max(300).allow('', null).optional(),
  brandPalette: Joi.array().items(Joi.string().trim().max(32)).max(8).optional(),
  infographic: infographicSchema.optional(),
  name: Joi.string().trim().max(255).optional(),
  contextId: Joi.string().uuid().allow(null, '').optional(),
}).custom((value, helpers) => {
  const mode = value.mode || 'image';
  if (mode === 'social' && !value.formatId) {
    return helpers.message('formatId is required for social mode');
  }
  const hasPrompt = value.prompt && String(value.prompt).trim();
  const hasSections = value.infographic?.sections?.length;
  if (!hasPrompt && !(mode === 'infographic' && hasSections)) {
    return helpers.message('prompt is required');
  }
  return value;
}, 'image gen generate validation');

const generateSchema = Joi.object({
  params: workspaceParams,
  body: generateBody,
});

const regenerateSchema = Joi.object({
  params: generationParams,
  body: Joi.object({
    mode: Joi.string().valid('image', 'infographic', 'social').optional(),
    modelId: Joi.string().trim().max(64).optional(),
    formatId: Joi.string().trim().max(64).allow(null, '').optional(),
    style: Joi.string().trim().max(64).allow(null, '').optional(),
    styleId: Joi.string().trim().max(64).allow(null, '').optional(),
    prompt: Joi.string().trim().max(4000).allow('', null).optional(),
    headline: Joi.string().trim().max(200).allow('', null).optional(),
    subheadline: Joi.string().trim().max(300).allow('', null).optional(),
    brandPalette: Joi.array().items(Joi.string().trim().max(32)).max(8).optional(),
    infographic: infographicSchema.optional(),
    name: Joi.string().trim().max(255).optional(),
    contextId: Joi.string().uuid().allow(null, '').optional(),
  }).default({}),
});

const tweakSchema = Joi.object({
  params: generationParams,
  body: Joi.object({
    instruction: Joi.string().trim().min(1).max(2000).required(),
  }),
});

const listGenerationsSchema = Joi.object({
  params: workspaceParams,
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
  }),
});

const getGenerationSchema = Joi.object({
  params: generationParams,
});

const estimateSchema = Joi.object({
  params: workspaceParams,
  query: Joi.object({
    modelId: Joi.string().trim().max(64).optional(),
    mode: Joi.string().valid('image', 'infographic', 'social').optional(),
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
