const { IMAGE_GEN_FEATURE, getModelAc } = require('../../../shared/config/imageGenCreditPricing');

const MODELS = Object.freeze([
  {
    id: 'gpt-image-1',
    name: 'GPT Image',
    description: 'Default OpenAI image model — strong general quality and readable text.',
    openaiModel: 'gpt-image-1',
    quality: 'medium',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE,
    modes: ['image'],
    recommended: true,
    supportsEdit: true,
  },
  {
    id: 'gpt-image-1-hd',
    name: 'GPT Image HD',
    description: 'Same model at high quality.',
    openaiModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
    modes: ['image'],
    recommended: false,
    supportsEdit: true,
  },
  {
    // Compatibility alias: OpenAI retired dall-e-3 (May 2026). Runs gpt-image-1 @ high.
    id: 'dall-e-3',
    name: 'DALL·E 3',
    description:
      'Legacy option — OpenAI retired DALL·E 3; we generate with GPT Image HD under the hood.',
    openaiModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.DALL_E_3,
    modes: ['image'],
    recommended: false,
    supportsEdit: true,
  },
]);

const MODEL_BY_ID = Object.freeze(Object.fromEntries(MODELS.map((m) => [m.id, m])));

function listModels() {
  return MODELS.map((m) => ({
    id: m.id,
    name: m.name,
    description: m.description,
    modes: m.modes,
    recommended: m.recommended,
    supportsEdit: m.supportsEdit,
    creditEstimate: getModelAc(m.id),
  }));
}

function defaultModelIdForMode(mode, modelId) {
  const trimmed = modelId != null ? String(modelId).trim() : '';
  if (trimmed) return trimmed;
  return 'gpt-image-1';
}

function resolveModel(modelId) {
  const id = modelId || 'gpt-image-1';
  return MODEL_BY_ID[id] || null;
}

function estimateCredits({ modelId, mode, isTweak = false }) {
  const resolvedModelId = defaultModelIdForMode(mode || 'image', modelId);
  const base = getModelAc(resolvedModelId);
  return {
    athenaCredits: base,
    breakdown: {
      modelId: resolvedModelId,
      modelAc: base,
      surcharge: 0,
      mode: isTweak ? 'tweak' : 'image',
    },
  };
}

module.exports = {
  MODELS,
  MODEL_BY_ID,
  listModels,
  defaultModelIdForMode,
  resolveModel,
  estimateCredits,
};
