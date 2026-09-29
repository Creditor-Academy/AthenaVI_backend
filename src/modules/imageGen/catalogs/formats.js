/**
 * Image Gen format catalog.
 * Generic formats serve `image` + `infographic`; social destinations serve `social` only;
 * print sizes serve `printable` only.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp crop.
 * geminiAspectRatio = native Gemini ratio closest to the target shape.
 */

const { resolveImageSize } = require('../../../shared/services/ai/geminiImage.service');

const GENERIC_MODES = Object.freeze(['image', 'infographic']);
const SOCIAL_MODES = Object.freeze(['social']);
const PRINT_MODES = Object.freeze(['printable']);

const MM_PER_INCH = 25.4;

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

const PRINT_COMPOSE_COMMON = [
  'Flat, print-ready graphic design artwork that fills the entire canvas edge to edge.',
  'This is the artwork file itself: NOT a photo or mockup of a printed poster, card, or invitation, no hands, tables, frames, walls, or perspective.',
  'Do not draw crop marks, trim lines, borders, or registration marks.',
  'Background color or imagery must continue all the way to every canvas edge (it extends into the print bleed).',
  'Clear typographic hierarchy with type sizes that are legible at the physical print size.',
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

function mmToPx(mm, dpi) {
  return Math.round((mm / MM_PER_INCH) * dpi);
}

const POSTER_LIMITS = Object.freeze({ headline: 60, subheadline: 120, details: 4, detailLine: 80, cta: 40 });

const PRINT_SPECS = [
  { id: 'poster-a4', name: 'A4 poster', kind: 'poster', widthMm: 210, heightMm: 297, dpi: 300 },
  { id: 'poster-a3', name: 'A3 poster', kind: 'poster', widthMm: 297, heightMm: 420, dpi: 150 },
  { id: 'poster-a2', name: 'A2 poster', kind: 'poster', widthMm: 420, heightMm: 594, dpi: 150 },
];

function posterFormat(spec, orientation) {
  const landscape = orientation === 'landscape';
  const widthMm = landscape ? spec.heightMm : spec.widthMm;
  const heightMm = landscape ? spec.widthMm : spec.heightMm;
  return {
    id: `${spec.id}-${orientation}`,
    name: `${spec.name} (${orientation})`,
    kind: spec.kind,
    widthMm,
    heightMm,
    dpi: spec.dpi,
    bleedMm: 3,
    safeMm: 5,
    orientation,
    aspectRatio: landscape ? '√2:1' : '1:√2',
    openaiSizeGpt: landscape ? '1536x1024' : '1024x1536',
    openaiSizeDalle: landscape ? '1792x1024' : '1024x1792',
    geminiAspectRatio: landscape ? '4:3' : '3:4',
    safeZone:
      'Keep all text and logos at least 5 mm inside the trim edge; background art runs to every edge.',
    printCompose: [
      landscape
        ? 'Landscape poster: strong left-to-right hierarchy, headline large enough to read from a few meters away.'
        : 'Portrait poster: headline in the upper third, supporting details below, readable from a few meters away.',
    ],
    textLimits: POSTER_LIMITS,
  };
}

/**
 * Print sizes: trim dimensions in mm (business card in inches), rendered with bleed.
 * `width`/`height` are trim pixels at `dpi`; `bleedMm` is added on every side of the render.
 */
const PRINT_FORMATS = [
  ...PRINT_SPECS.flatMap((spec) => [posterFormat(spec, 'portrait'), posterFormat(spec, 'landscape')]),
  {
    id: 'business-card',
    name: 'Business card (3.5 x 2 in)',
    kind: 'business_card',
    widthMm: 3.5 * MM_PER_INCH,
    heightMm: 2 * MM_PER_INCH,
    widthIn: 3.5,
    heightIn: 2,
    dpi: 300,
    bleedMm: 0.125 * MM_PER_INCH,
    safeMm: 0.125 * MM_PER_INCH,
    orientation: 'landscape',
    aspectRatio: '7:4',
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    geminiAspectRatio: '16:9',
    safeZone:
      'Keep name, title, contact lines, and logo at least 1/8 in inside the trim edge.',
    printCompose: [
      'Front of a professional business card: name most prominent, title/company second, contact lines small but legible.',
      'Generous whitespace; no photos of people unless the prompt asks for one.',
    ],
    textLimits: { headline: 40, subheadline: 60, details: 4, detailLine: 48, cta: 0 },
  },
  {
    id: 'invitation-a6-portrait',
    name: 'Invitation (105 x 148 mm, portrait)',
    kind: 'invitation',
    widthMm: 105,
    heightMm: 148,
    dpi: 300,
    bleedMm: 3,
    safeMm: 5,
    orientation: 'portrait',
    aspectRatio: '1:√2',
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    geminiAspectRatio: '3:4',
    safeZone: 'Keep all text at least 5 mm inside the trim edge.',
    printCompose: [
      'Elegant invitation card: event title prominent, host line, then date, time, venue, and RSVP details in a clear block.',
    ],
    textLimits: { headline: 60, subheadline: 100, details: 5, detailLine: 70, cta: 40 },
  },
].map((f) => ({
  ...f,
  category: 'print',
  platform: null,
  modes: PRINT_MODES,
  width: mmToPx(f.widthMm, f.dpi),
  height: mmToPx(f.heightMm, f.dpi),
  safeArea: null,
}));

const FORMATS = Object.freeze([...GENERIC_FORMATS, ...SOCIAL_FORMATS, ...PRINT_FORMATS]);

const FORMAT_BY_ID = Object.freeze(Object.fromEntries(FORMATS.map((f) => [f.id, f])));

const SOCIAL_FORMAT_IDS = Object.freeze(SOCIAL_FORMATS.map((f) => f.id));
const PRINT_FORMAT_IDS = Object.freeze(PRINT_FORMATS.map((f) => f.id));

/**
 * Render canvas for a print format: trim plus bleed on every side, in pixels.
 * `offsetX`/`offsetY` locate the trim box inside the bleed canvas.
 */
function bleedCanvasFor(format) {
  if (!format || format.category !== 'print') return null;
  const bleedPx = mmToPx(format.bleedMm, format.dpi);
  const safePx = mmToPx(format.safeMm, format.dpi);
  return {
    width: format.width + bleedPx * 2,
    height: format.height + bleedPx * 2,
    offsetX: bleedPx,
    offsetY: bleedPx,
    bleedPx,
    safePx,
    dpi: format.dpi,
  };
}

function printInfo(format) {
  if (!format || format.category !== 'print') return null;
  const canvas = bleedCanvasFor(format);
  return {
    kind: format.kind,
    orientation: format.orientation,
    widthMm: Math.round(format.widthMm * 100) / 100,
    heightMm: Math.round(format.heightMm * 100) / 100,
    widthIn: format.widthIn || null,
    heightIn: format.heightIn || null,
    dpi: format.dpi,
    bleedMm: Math.round(format.bleedMm * 100) / 100,
    safeMm: Math.round(format.safeMm * 100) / 100,
    bleedWidth: canvas.width,
    bleedHeight: canvas.height,
  };
}

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
    print: printInfo(f),
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
  const requested =
    format && format.category === 'print'
      ? process.env.IMAGE_GEN_PRINT_GEMINI_IMAGE_SIZE || '2K'
      : undefined;
  return {
    aspectRatio: (format && format.geminiAspectRatio) || '1:1',
    imageSize: resolveImageSize(requested, model.maxImageSize),
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
  if (mode === 'printable') {
    return {
      composeRules: [...PRINT_COMPOSE_COMMON, ...(format.printCompose || [])],
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
  PRINT_FORMAT_IDS,
  MM_PER_INCH,
  mmToPx,
  bleedCanvasFor,
  printInfo,
  listFormats,
  resolveFormat,
  isFormatForMode,
  defaultFormatIdForMode,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
  composeRulesForMode,
};
