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
    supportsEdit: true,
  },
  {
    id: 'gpt-image-1-hd',
    name: 'GPT Image HD',
    description: 'Same model at high quality — best for social banners and infographics.',
    openaiModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
    modes: ['image', 'infographic', 'social'],
    recommended: false,
    supportsEdit: true,
  },
  {
    id: 'dall-e-3',
    name: 'DALL·E 3',
    description: 'OpenAI DALL·E 3 — creative variety. Tweaks use GPT Image edit under the hood.',
    openaiModel: 'dall-e-3',
    quality: 'standard',
    feature: IMAGE_GEN_FEATURE.DALL_E_3,
    modes: ['image', 'social'],
    recommended: false,
    supportsEdit: false,
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
    supportsEdit: m.supportsEdit,
    creditEstimate: getModelAc(m.id),
  }));
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
  const base = getModelAc(modelId || 'gpt-image-1');
  if (isTweak) {
    return {
      athenaCredits: base,
      breakdown: {
        modelId: modelId || 'gpt-image-1',
        modelAc: base,
        surcharge: 0,
        mode: 'tweak',
      },
    };
  }
  const surcharge = getModeSurcharge(mode);
  return {
    athenaCredits: base + surcharge,
    breakdown: {
      modelId: modelId || 'gpt-image-1',
      modelAc: base,
      surcharge,
      mode: mode || 'image',
    },
  };
}

module.exports = {
  MODELS,
  MODEL_BY_ID,
  listModels,
  resolveModel,
  estimateCredits,
};
