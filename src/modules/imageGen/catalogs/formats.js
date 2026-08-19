/**
 * Generic image format catalog.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp cover-crop.
 */

const FULL_BLEED_COMMON = [
  'FULL-BLEED edge-to-edge: fill the entire canvas.',
  'No letterboxing, borders, empty side bars, floating cards, or large plain unused regions.',
  'No separate solid color panels used as filler.',
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
    safeZone: 'Keep subject centered with comfortable margins.',
    composeRules: [...FULL_BLEED_COMMON, '1:1 square composition; balanced center focus.'],
  },
  {
    id: 'landscape',
    name: 'Landscape',
    category: 'generic',
    width: 1536,
    height: 1024,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Keep focal content in the center third.',
    composeRules: [...FULL_BLEED_COMMON, 'Landscape 3:2; keep hero in the center third.'],
  },
  {
    id: 'portrait',
    name: 'Portrait',
    category: 'generic',
    width: 1024,
    height: 1536,
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    safeZone: 'Keep focal content in the center third.',
    composeRules: [...FULL_BLEED_COMMON, 'Portrait 2:3; keep hero in the center third.'],
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

function openaiSizeForFormat(format, openaiModel) {
  if (!format) {
    return '1024x1024';
  }
  if (String(openaiModel || '').startsWith('dall-e')) {
    return format.openaiSizeDalle;
  }
  return format.openaiSizeGpt;
}

module.exports = {
  FORMATS,
  FORMAT_BY_ID,
  listFormats,
  resolveFormat,
  openaiSizeForFormat,
};
