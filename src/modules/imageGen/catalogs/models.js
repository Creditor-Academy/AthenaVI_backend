const {
  IMAGE_GEN_FEATURE,
  getModelAc,
  getModeSurcharge,
} = require('../../../shared/config/imageGenCreditPricing');

const MODELS = Object.freeze([
  {
    id: 'gpt-image-1',
    name: 'GPT Image',
    description: 'Default OpenAI image model — strong general quality and readable text.',
    openaiModel: 'gpt-image-1',
    quality: 'medium',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE,
    modes: ['image', 'infographic', 'social'],
    recommended: true,
    recommendedForModes: ['image', 'social'],
    supportsEdit: true,
  },
  {
    id: 'gpt-image-1-hd',
    name: 'GPT Image HD',
    description: 'Same model at high quality — default for infographics; best for social banners.',
    openaiModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
    modes: ['image', 'infographic', 'social'],
    recommended: false,
    recommendedForModes: ['infographic'],
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
    modes: ['image', 'social'],
    recommended: false,
    recommendedForModes: [],
    supportsEdit: true,
  },
]);

const MODEL_BY_ID = Object.freeze(
  Object.fromEntries(MODELS.map((m) => [m.id, m]))
);

function listModels() {
  return MODELS.map((m) => ({
    id: m.id,
    name: m.name,
    description: m.description,
    modes: m.modes,
    recommended: m.recommended,
    recommendedForModes: m.recommendedForModes || [],
    supportsEdit: m.supportsEdit,
    creditEstimate: getModelAc(m.id),
  }));
}

function defaultModelIdForMode(mode, modelId) {
  const trimmed = modelId != null ? String(modelId).trim() : '';
  if (trimmed) return trimmed;
  if (mode === 'infographic') return 'gpt-image-1-hd';
  return 'gpt-image-1';
}

function resolveModel(modelId) {
  const id = modelId || 'gpt-image-1';
  const model = MODEL_BY_ID[id];
  if (!model) {
    return null;
  }
  return model;
}

function estimateCredits({ modelId, mode, isTweak = false }) {
  const resolvedMode = mode || 'image';
  const resolvedModelId = defaultModelIdForMode(resolvedMode, modelId);
  const base = getModelAc(resolvedModelId);
  if (isTweak) {
    return {
      athenaCredits: base,
      breakdown: {
        modelId: resolvedModelId,
        modelAc: base,
        surcharge: 0,
        mode: 'tweak',
      },
    };
  }
  const surcharge = getModeSurcharge(resolvedMode);
  return {
    athenaCredits: base + surcharge,
    breakdown: {
      modelId: resolvedModelId,
      modelAc: base,
      surcharge,
      mode: resolvedMode,
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
