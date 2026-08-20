const { DEFAULT_SLIDE_MODEL } = require('../../../shared/services/ai/llm.service');

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function clampTopN(n) {
  return Math.min(10, Math.max(5, Math.round(n)));
}

function getLayoutAiSelectionConfig(overrides = {}) {
  const topN = clampTopN(envNumber('PPT_LAYOUT_AI_TOP_N', 8));
  return {
    aiEnabled: String(process.env.PPT_LAYOUT_AI_ENABLED || 'true').trim().toLowerCase() !== 'false',
    model: process.env.PPT_LAYOUT_SELECT_MODEL || DEFAULT_SLIDE_MODEL || 'gpt-4.1-mini',
    aiSelectionMinConfidence: envNumber('PPT_LAYOUT_AI_MIN_CONFIDENCE', 70),
    topN,
    cacheTtlMs: envNumber('PPT_LAYOUT_AI_CACHE_TTL_MS', 10 * 60 * 1000),
    cacheMaxEntries: envNumber('PPT_LAYOUT_AI_CACHE_MAX', 200),
    timeoutMs: envNumber('PPT_LAYOUT_AI_TIMEOUT_MS', 20000),
    temperature: 0.2,
    ...overrides,
  };
}

const AI_LAYOUT_SELECTION_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['selectedLayoutId', 'confidence', 'reason'],
  properties: {
    selectedLayoutId: {
      type: 'string',
      description: 'Must be exactly one of the supplied candidate layout IDs',
    },
    confidence: {
      type: 'number',
      minimum: 0,
      maximum: 100,
      description: '0-100 confidence in the selection',
    },
    reason: {
      type: 'string',
      description: 'One or two sentences explaining the semantic fit',
    },
    alternativeLayoutId: {
      type: 'string',
      description: 'Optional runner-up that must also be a supplied candidate ID',
    },
  },
};

module.exports = {
  getLayoutAiSelectionConfig,
  AI_LAYOUT_SELECTION_SCHEMA,
};
