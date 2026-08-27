/**
 * Generic image format catalog.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp crop.
 * geminiAspectRatio = native Gemini ratio so the render matches the target shape.
 */

const { resolveImageSize } = require('../../../shared/services/ai/geminiImage.service');

const FULL_BLEED_COMMON = [
  'FULL-BLEED edge-to-edge: fill the entire canvas.',
  'No letterboxing, borders, empty side bars, floating cards, or large plain unused regions.',
  'No separate solid color panels used as filler.',
];

const INFOGRAPHIC_COMPOSE_COMMON = [
  'Infographic layout: allow margins, card blocks, legends, and readable whitespace.',
  'Do NOT use full-bleed photographic fill; prefer clean panels, icons, and typography.',
  'Keep all text, labels, and numbers fully inside the canvas — never clip edges.',
  'Leave comfortable padding from the canvas border (safe margins).',
];

const FORMATS = Object.freeze([
  {
    id: 'square',
    name: 'Square',
    category: 'generic',
    width: 1024,
    height: 1024,
    openaiSizeGpt: '1024x1024',
    openaiSizeDalle: '1024x1024',
    geminiAspectRatio: '1:1',
    safeZone: 'Keep subject centered with comfortable margins.',
    composeRules: [...FULL_BLEED_COMMON, '1:1 square composition; balanced center focus.'],
    infographicCompose: [
      ...INFOGRAPHIC_COMPOSE_COMMON,
      '1:1 square canvas; balanced grid or centered structure; avoid overcrowding.',
    ],
    infographicSafeZone: 'Keep title and all labels inside padded margins; no edge clipping.',
  },
  {
    id: 'landscape',
    name: 'Landscape',
    category: 'generic',
    width: 1536,
    height: 1024,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '3:2',
    safeZone: 'Keep focal content in the center third.',
    composeRules: [...FULL_BLEED_COMMON, 'Landscape 3:2; keep hero in the center third.'],
    infographicCompose: [
      ...INFOGRAPHIC_COMPOSE_COMMON,
      'Landscape ~3:2 canvas; prefer left-to-right flows and side-by-side columns when content allows.',
    ],
    infographicSafeZone: 'Keep title and all labels inside padded margins; no edge clipping.',
  },
  {
    id: 'portrait',
    name: 'Portrait',
    category: 'generic',
    width: 1024,
    height: 1536,
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    geminiAspectRatio: '2:3',
    safeZone: 'Keep focal content in the center third.',
    composeRules: [...FULL_BLEED_COMMON, 'Portrait 2:3; keep hero in the center third.'],
    infographicCompose: [
      ...INFOGRAPHIC_COMPOSE_COMMON,
      'Portrait ~2:3 canvas; prefer top-to-bottom stacks and vertical flows when content allows.',
    ],
    infographicSafeZone: 'Keep title and all labels inside padded margins; no edge clipping.',
  },
]);

const FORMAT_BY_ID = Object.freeze(Object.fromEntries(FORMATS.map((f) => [f.id, f])));

function listFormats() {
  return FORMATS.map((f) => ({
    id: f.id,
    name: f.name,
    category: f.category,
    width: f.width,
    height: f.height,
    safeZone: f.safeZone,
  }));
}

function resolveFormat(formatId) {
  if (!formatId) return null;
  return FORMAT_BY_ID[formatId] || null;
}

function openaiSizeForFormat(format, providerModel) {
  if (!format) {
    return '1024x1024';
  }
  if (String(providerModel || '').startsWith('dall-e')) {
    return format.openaiSizeDalle;
  }
  return format.openaiSizeGpt;
}

/**
 * Native Gemini image config for a format, clamped to what the model supports.
 * @param {object} format
 * @param {{ maxImageSize?: string }} [model]
 */
function geminiImageConfigForFormat(format, model = {}) {
  return {
    aspectRatio: (format && format.geminiAspectRatio) || '1:1',
    imageSize: resolveImageSize(undefined, model.maxImageSize),
  };
}

/**
 * Compose / safe-zone rules for the given mode.
 * Image mode keeps full-bleed rules; infographic uses margin-friendly rules.
 */
function composeRulesForMode(format, mode = 'image') {
  if (!format) {
    return { composeRules: [], safeZone: '' };
  }
  if (mode === 'infographic') {
    return {
      composeRules: format.infographicCompose || INFOGRAPHIC_COMPOSE_COMMON,
      safeZone: format.infographicSafeZone || format.safeZone || '',
    };
  }
  return {
    composeRules: format.composeRules || [],
    safeZone: format.safeZone || '',
  };
}

module.exports = {
  FORMATS,
  FORMAT_BY_ID,
  listFormats,
  resolveFormat,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
  composeRulesForMode,
};
