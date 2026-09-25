/**
 * Image Gen format catalog.
 * Generic formats serve `image` + `infographic`; social destinations serve `social` only.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp crop.
 * geminiAspectRatio = native Gemini ratio closest to the target shape.
 */

const { resolveImageSize } = require('../../../shared/services/ai/geminiImage.service');

const GENERIC_MODES = Object.freeze(['image', 'infographic']);
const SOCIAL_MODES = Object.freeze(['social']);

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

const SOCIAL_COMPOSE_COMMON = [
  'Social media graphic: fill the whole canvas edge to edge with background art — no borders, letterboxing, or empty bars.',
  'Typography must be large, bold, and legible at small phone sizes; high contrast between text and background.',
  'Use at most three text elements (headline, optional supporting line, optional call to action).',
  'Never place text or logos against the canvas edges.',
];

const GENERIC_FORMATS = [
  {
    id: 'square',
    name: 'Square',
    category: 'generic',
    platform: null,
    modes: GENERIC_MODES,
    width: 1024,
    height: 1024,
    aspectRatio: '1:1',
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
    platform: null,
    modes: GENERIC_MODES,
    width: 1536,
    height: 1024,
    aspectRatio: '3:2',
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
    platform: null,
    modes: GENERIC_MODES,
    width: 1024,
    height: 1536,
    aspectRatio: '2:3',
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
  {
    id: 'landscape-16-9',
    name: 'Widescreen (16:9)',
    category: 'generic',
    platform: null,
    modes: GENERIC_MODES,
    width: 1792,
    height: 1024,
    aspectRatio: '16:9',
    openaiSizeGpt: '1792x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '16:9',
    safeZone: 'Keep focal content in the center.',
    composeRules: [...FULL_BLEED_COMMON, 'Widescreen 16:9 cinematic framing.'],
    infographicCompose: [
      ...INFOGRAPHIC_COMPOSE_COMMON,
      'Widescreen 16:9 canvas; use wide horizontal timeline or side-by-side comparison panels.',
    ],
    infographicSafeZone: 'Keep title and all labels inside padded margins.',
  },
  {
    id: 'portrait-9-16',
    name: 'Vertical (9:16)',
    category: 'generic',
    platform: null,
    modes: GENERIC_MODES,
    width: 1024,
    height: 1792,
    aspectRatio: '9:16',
    openaiSizeGpt: '1024x1792',
    openaiSizeDalle: '1024x1792',
    geminiAspectRatio: '9:16',
    safeZone: 'Keep focal content in the center.',
    composeRules: [...FULL_BLEED_COMMON, 'Vertical 9:16 framing for mobile.'],
    infographicCompose: [
      ...INFOGRAPHIC_COMPOSE_COMMON,
      'Vertical 9:16 canvas; use vertical scrolling structure or stacked panels.',
    ],
    infographicSafeZone: 'Keep title and all labels inside padded margins.',
  },
];

/**
 * `safeArea` (px, centered) is the region every viewer is guaranteed to see.
 * `textLimits` caps on-image copy (characters) so text stays legible at feed size.
 */
const SOCIAL_FORMATS = [
  {
    id: 'youtube-thumbnail',
    name: 'YouTube thumbnail',
    platform: 'youtube',
    width: 1280,
    height: 720,
    aspectRatio: '16:9',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '16:9',
    safeArea: null,
    safeZone:
      'Keep all text inside a small outer margin and out of the bottom-right corner, where YouTube overlays the video duration.',
    socialCompose: [
      'One large, punchy title and one strong focal subject (face, product, or object) with dramatic contrast.',
      'Design for tiny preview sizes: very few words, very large type.',
    ],
    textLimits: { headline: 40, supportingText: 0, cta: 0 },
  },
  {
    id: 'instagram-post',
    name: 'Instagram post',
    platform: 'instagram',
    width: 1080,
    height: 1350,
    aspectRatio: '4:5',
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    geminiAspectRatio: '4:5',
    safeArea: null,
    safeZone:
      'Keep all text inside comfortable side margins and away from the bottom edge.',
    socialCompose: [
      'Vertical poster composition for the Instagram feed.',
      'Headline in the upper or middle third; optional supporting line and call to action below it.',
    ],
    textLimits: { headline: 60, supportingText: 110, cta: 24 },
  },
  {
    id: 'facebook-post',
    name: 'Facebook post',
    platform: 'facebook',
    width: 940,
    height: 788,
    aspectRatio: '47:39',
    openaiSizeGpt: '1024x1024',
    openaiSizeDalle: '1024x1024',
    geminiAspectRatio: '5:4',
    safeArea: null,
    safeZone: 'Keep text away from all edges, inside a generous margin.',
    socialCompose: [
      'Feed image with one clear focal subject and short on-image copy.',
    ],
    textLimits: { headline: 60, supportingText: 100, cta: 24 },
  },
  {
    id: 'facebook-cover',
    name: 'Facebook cover',
    platform: 'facebook',
    width: 851,
    height: 315,
    aspectRatio: '851:315',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '21:9',
    safeArea: null,
    safeZone:
      'Keep the message in the upper-center and right side; the page profile picture covers the lower-left corner.',
    socialCompose: [
      'Wide cover banner: atmospheric background art with the message placed right of center.',
      'Leave the lower-left area free of text, logos, and faces.',
    ],
    textLimits: { headline: 50, supportingText: 80, cta: 0 },
  },
  {
    id: 'youtube-banner',
    name: 'YouTube banner',
    platform: 'youtube',
    width: 2560,
    height: 1440,
    aspectRatio: '16:9',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '16:9',
    safeArea: { width: 1546, height: 423 },
    safeZone:
      'All text and logos must sit inside the centered 1546x423 safe area (about the middle 60% of width and 29% of height). TVs show the full canvas; desktop and mobile crop to a short band around the center.',
    socialCompose: [
      'Background art may fill the full canvas and should extend naturally beyond the safe area.',
      'Channel name or headline inside the centered safe area only.',
    ],
    textLimits: { headline: 40, supportingText: 60, cta: 0 },
  },
  {
    id: 'twitter-post',
    name: 'X / Twitter post',
    platform: 'twitter',
    width: 1600,
    height: 900,
    aspectRatio: '16:9',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '16:9',
    safeArea: null,
    safeZone: 'Keep text inside the center of the canvas and away from the edges.',
    socialCompose: [
      'Wide post image with a short headline and one focal subject.',
    ],
    textLimits: { headline: 60, supportingText: 90, cta: 24 },
  },
  {
    id: 'linkedin-banner',
    name: 'LinkedIn banner',
    platform: 'linkedin',
    width: 1584,
    height: 396,
    aspectRatio: '4:1',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '21:9',
    safeArea: null,
    safeZone:
      'Keep text and logos on the right side and upper portion; the profile photo covers the lower-left area.',
    socialCompose: [
      'Very wide, professional banner: calm background art with the message placed right of center.',
      'Leave the left third mostly free of text and faces.',
    ],
    textLimits: { headline: 50, supportingText: 80, cta: 0 },
  },
].map((f) => ({ ...f, category: 'social', modes: SOCIAL_MODES }));

const FORMATS = Object.freeze([...GENERIC_FORMATS, ...SOCIAL_FORMATS]);

const FORMAT_BY_ID = Object.freeze(Object.fromEntries(FORMATS.map((f) => [f.id, f])));

const SOCIAL_FORMAT_IDS = Object.freeze(SOCIAL_FORMATS.map((f) => f.id));

const DEFAULT_FORMAT_BY_MODE = Object.freeze({
  image: 'square',
  infographic: 'landscape',
});

function listFormats() {
  return FORMATS.map((f) => ({
    id: f.id,
    name: f.name,
    category: f.category,
    platform: f.platform,
    modes: [...f.modes],
    width: f.width,
    height: f.height,
    aspectRatio: f.aspectRatio,
    safeZone: f.safeZone,
    safeArea: f.safeArea || null,
  }));
}

function resolveFormat(formatId) {
  if (!formatId) return null;
  return FORMAT_BY_ID[formatId] || null;
}

function isFormatForMode(format, mode) {
  return Boolean(format && Array.isArray(format.modes) && format.modes.includes(mode));
}

function defaultFormatIdForMode(mode) {
  return DEFAULT_FORMAT_BY_MODE[mode] || null;
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
 * Image mode keeps full-bleed rules; infographic uses margin-friendly rules;
 * social uses platform rules on a full-bleed canvas.
 */
function composeRulesForMode(format, mode = 'image') {
  if (!format) {
    return { composeRules: [], safeZone: '' };
  }
  if (mode === 'social') {
    return {
      composeRules: [...SOCIAL_COMPOSE_COMMON, ...(format.socialCompose || [])],
      safeZone: format.safeZone || '',
    };
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
  SOCIAL_FORMAT_IDS,
  listFormats,
  resolveFormat,
  isFormatForMode,
  defaultFormatIdForMode,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
  composeRulesForMode,
};
