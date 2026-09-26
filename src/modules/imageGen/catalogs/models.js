const {
  IMAGE_GEN_FEATURE,
  getModelAc,
  getInfographicAc,
  getSocialAc,
} = require('../../../shared/config/imageGenCreditPricing');

const ALL_MODES = Object.freeze(['image', 'infographic', 'social']);

const MODELS = Object.freeze([
  {
    id: 'gpt-image-1',
    name: 'GPT Image',
    description: 'OpenAI image model at standard quality — faster and cheaper than HD.',
    provider: 'openai',
    providerModel: 'gpt-image-1',
    quality: 'medium',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE,
    modes: ALL_MODES,
    recommended: false,
    supportsEdit: true,
  },
  {
    id: 'gpt-image-1-hd',
    name: 'GPT Image HD',
    description: 'OpenAI image model at high quality. Default for general images.',
    provider: 'openai',
    providerModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
    modes: ALL_MODES,
    recommended: true,
    supportsEdit: true,
  },
  {
    // Compatibility alias: OpenAI retired dall-e-3 (May 2026). Runs gpt-image-1 @ high.
    id: 'dall-e-3',
    name: 'DALL·E 3',
    description:
      'Legacy option — OpenAI retired DALL·E 3; we generate with GPT Image HD under the hood.',
    provider: 'openai',
    providerModel: 'gpt-image-1',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.DALL_E_3,
    modes: ALL_MODES,
    recommended: false,
    supportsEdit: true,
  },
  {
    id: 'gemini-3-pro-image',
    name: 'Nano Banana Pro',
    description:
      'Google model with the best in-image text and diagrams. Default for infographics and social posts.',
    provider: 'gemini',
    providerModel: 'gemini-3-pro-image',
    maxImageSize: '4K',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GEMINI_PRO_IMAGE,
    modes: ALL_MODES,
    recommended: false,
    supportsEdit: true,
  },
  {
    id: 'gemini-3.1-flash-image',
    name: 'Nano Banana 2',
    description:
      'Balanced Google model — fast, good text rendering, strong with reference images.',
    provider: 'gemini',
    providerModel: 'gemini-3.1-flash-image',
    maxImageSize: '4K',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GEMINI_FLASH_IMAGE,
    modes: ALL_MODES,
    recommended: false,
    supportsEdit: true,
  },
  {
    id: 'gemini-3.1-flash-lite-image',
    name: 'Nano Banana 2 Lite',
    description:
      'Fastest and cheapest Google model. Renders at 1K only, so best for drafts and high volume.',
    provider: 'gemini',
    providerModel: 'gemini-3.1-flash-lite-image',
    maxImageSize: '1K',
    quality: 'high',
    feature: IMAGE_GEN_FEATURE.GEMINI_FLASH_LITE_IMAGE,
    modes: ALL_MODES,
    recommended: false,
    supportsEdit: true,
  },
]);

const MODEL_BY_ID = Object.freeze(Object.fromEntries(MODELS.map((m) => [m.id, m])));

/** Picker groups in display order; the first id of each group is its default. */
const PROVIDERS = Object.freeze([
  {
    id: 'openai',
    name: 'OpenAI',
    modelIds: ['gpt-image-1-hd', 'gpt-image-1', 'dall-e-3'],
  },
  {
    id: 'gemini',
    name: 'Gemini',
    modelIds: ['gemini-3-pro-image', 'gemini-3.1-flash-image', 'gemini-3.1-flash-lite-image'],
  },
]);

const DEFAULT_PROVIDER_MODEL = Object.freeze({
  openai: 'gpt-image-1-hd',
  gemini: 'gemini-3-pro-image',
});

const MODE_DEFAULTS = Object.freeze({
  image: { provider: 'openai', modelId: 'gpt-image-1-hd', recommendedProvider: 'openai' },
  infographic: { provider: 'gemini', modelId: 'gemini-3-pro-image', recommendedProvider: null },
  social: { provider: 'gemini', modelId: 'gemini-3-pro-image', recommendedProvider: null },
});

function creditEstimateFor(model) {
  return getModelAc(model.id);
}

function listModels() {
  return MODELS.map((m) => ({
    id: m.id,
    name: m.name,
    description: m.description,
    provider: m.provider,
    quality: m.quality,
    maxImageSize: m.maxImageSize || null,
    modes: m.modes,
    recommended: m.recommended,
    supportsEdit: m.supportsEdit,
    creditEstimate: creditEstimateFor(m),
  }));
}

function listProviders() {
  return PROVIDERS.map((p) => ({
    id: p.id,
    name: p.name,
    defaultModelId: DEFAULT_PROVIDER_MODEL[p.id],
    modelIds: [...p.modelIds],
  }));
}

function listModeDefaults() {
  return Object.fromEntries(
    Object.entries(MODE_DEFAULTS).map(([mode, value]) => [mode, { ...value }])
  );
}

/** Full `GET /models` payload: flat list, provider groups, and per-mode defaults. */
function modelCatalog() {
  return {
    models: listModels(),
    providers: listProviders(),
    defaults: listModeDefaults(),
    defaultProviderModel: { ...DEFAULT_PROVIDER_MODEL },
  };
}

function defaultModelIdForMode(mode, modelId) {
  const trimmed = modelId != null ? String(modelId).trim() : '';
  if (trimmed) return trimmed;
  return (MODE_DEFAULTS[mode] || MODE_DEFAULTS.image).modelId;
}

function resolveModel(modelId) {
  const id = modelId || MODE_DEFAULTS.image.modelId;
  return MODEL_BY_ID[id] || null;
}

function modeAc(mode, modelId) {
  if (mode === 'infographic') return getInfographicAc(modelId);
  if (mode === 'social') return getSocialAc(modelId);
  return getModelAc(modelId);
}

function modeFeature(mode) {
  if (mode === 'infographic') return IMAGE_GEN_FEATURE.INFOGRAPHIC;
  if (mode === 'social') return IMAGE_GEN_FEATURE.SOCIAL;
  return undefined;
}

function estimateCredits({ modelId, mode, isTweak = false }) {
  const resolvedMode = mode || 'image';
  const resolvedModelId = defaultModelIdForMode(resolvedMode, modelId);
  const base = modeAc(resolvedMode, resolvedModelId);
  return {
    athenaCredits: base,
    breakdown: {
      modelId: resolvedModelId,
      modelAc: base,
      surcharge: 0,
      mode: isTweak ? 'tweak' : resolvedMode,
      feature: modeFeature(resolvedMode),
    },
  };
}

module.exports = {
  MODELS,
  MODEL_BY_ID,
  PROVIDERS,
  DEFAULT_PROVIDER_MODEL,
  MODE_DEFAULTS,
  listModels,
  listProviders,
  listModeDefaults,
  modelCatalog,
  defaultModelIdForMode,
  resolveModel,
  modeAc,
  modeFeature,
  estimateCredits,
};
