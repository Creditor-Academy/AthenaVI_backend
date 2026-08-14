const Joi = require('joi');

/** Freeform generate/regenerate prompt (image, infographic, social). */
const IMAGE_GEN_PROMPT_MAX = 16_000;
/** Tweak follow-up instruction. */
const IMAGE_GEN_TWEAK_INSTRUCTION_MAX = 4_000;
/** Infographic panel body (structured form). */
const INFOGRAPHIC_SECTION_CONTENT_MAX = 8_000;
const INFOGRAPHIC_BULLET_MAX = 1_000;
const INFOGRAPHIC_TITLE_MAX = 200;
const INFOGRAPHIC_SECTION_MAX = 12;
const INFOGRAPHIC_BULLETS_PER_SECTION_MAX = 20;

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
  title: Joi.string().trim().max(INFOGRAPHIC_TITLE_MAX).allow('', null).optional(),
  sections: Joi.array()
    .items(
      Joi.object({
        title: Joi.string().trim().max(INFOGRAPHIC_TITLE_MAX).allow('', null).optional(),
        bullets: Joi.array()
          .items(Joi.string().trim().max(INFOGRAPHIC_BULLET_MAX))
          .max(INFOGRAPHIC_BULLETS_PER_SECTION_MAX)
          .optional(),
        content: Joi.string().trim().max(INFOGRAPHIC_SECTION_CONTENT_MAX).allow('', null).optional(),
      })
    )
    .max(INFOGRAPHIC_SECTION_MAX)
    .optional(),
}).unknown(true);

const generateBody = Joi.object({
  mode: Joi.string().valid('image', 'infographic', 'social').default('image'),
  modelId: Joi.string().trim().max(64).default('gpt-image-1'),
  formatId: Joi.string().trim().max(64).allow(null, '').optional(),
  style: Joi.string().trim().max(64).allow(null, '').optional(),
  styleId: Joi.string().trim().max(64).allow(null, '').optional(),
  prompt: Joi.string().trim().max(IMAGE_GEN_PROMPT_MAX).allow('', null).optional(),
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
    prompt: Joi.string().trim().max(IMAGE_GEN_PROMPT_MAX).allow('', null).optional(),
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
    instruction: Joi.string().trim().min(1).max(IMAGE_GEN_TWEAK_INSTRUCTION_MAX).required(),
  }),
});

const listGenerationsSchema = Joi.object({
  params: workspaceParams,
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    mode: Joi.string().valid('image', 'infographic', 'social').optional(),
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
  IMAGE_GEN_PROMPT_MAX,
  IMAGE_GEN_TWEAK_INSTRUCTION_MAX,
  INFOGRAPHIC_SECTION_CONTENT_MAX,
  INFOGRAPHIC_BULLET_MAX,
  INFOGRAPHIC_TITLE_MAX,
  INFOGRAPHIC_SECTION_MAX,
  INFOGRAPHIC_BULLETS_PER_SECTION_MAX,
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
