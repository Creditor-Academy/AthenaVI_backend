/**
 * Social + generic format catalog.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp cover-crop.
 * composeRules = model instructions for full-bleed layout per platform size.
 */

const FULL_BLEED_COMMON = [
  'FULL-BLEED edge-to-edge: fill the entire canvas.',
  'No letterboxing, borders, empty side bars, floating cards, or large plain unused regions.',
  'No separate solid color panels used as filler.',
];

const INSET_10 = Object.freeze({ top: 0.1, right: 0.1, bottom: 0.1, left: 0.1 });

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
    overlayInsets: null,
    overlayAlign: null,
    recommendedTextMode: null,
    composeRules: [
      ...FULL_BLEED_COMMON,
      '1:1 square composition; balanced center focus.',
    ],
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
    overlayInsets: null,
    overlayAlign: null,
    recommendedTextMode: null,
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Landscape 3:2; keep hero in the center third.',
    ],
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
    overlayInsets: null,
    overlayAlign: null,
    recommendedTextMode: null,
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Portrait 2:3; keep hero in the center third.',
    ],
  },
  {
    id: 'linkedin_banner',
    name: 'LinkedIn banner',
    category: 'social',
    width: 1584,
    height: 396,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1584×396 (~4:1) profile banner. Full-bleed texture across the full width. Keep text center-right; left ~25% subtle for profile photo overlap.',
    overlayInsets: Object.freeze({ top: 0.12, right: 0.1, bottom: 0.12, left: 0.25 }),
    overlayAlign: 'center-right',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Ultra-wide LinkedIn PROFILE BANNER (~4:1 panoramic strip).',
      'Visual texture and gradients must continue LEFT EDGE → RIGHT EDGE with no empty sides.',
      'LEFT ~25%: subtle low-contrast texture only (profile photo overlaps here) — no text, logos, faces, or strong focal objects.',
      'CENTER → RIGHT: stronger detail; place headline around center-right, not far left.',
      'All critical content stays in the vertical CENTER band (top/bottom may be cropped from source).',
      'Side margins ≥10% for any text.',
    ],
  },
  {
    id: 'linkedin_post',
    name: 'LinkedIn post',
    category: 'social',
    width: 1200,
    height: 627,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1200×627 (~1.91:1) feed post. Full-bleed; large readable headline centered with ≥10% margins.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'LinkedIn FEED POST (~1.91:1 landscape).',
      'Single continuous scene filling the frame — professional, clean, high contrast.',
      'Headline large and centered (or slight left of center); ≥10% margin from all edges.',
      'Avoid tiny text; design must read clearly in the LinkedIn feed thumbnail.',
    ],
  },
  {
    id: 'instagram_post',
    name: 'Instagram post',
    category: 'social',
    width: 1080,
    height: 1080,
    openaiSizeGpt: '1024x1024',
    openaiSizeDalle: '1024x1024',
    safeZone:
      '1080×1080 (1:1) feed post. Bold centered composition; text fully inside ≥8% margins.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Instagram FEED POST (1:1 square).',
      'Bold centered composition that fills the square edge-to-edge.',
      'Text fully on-canvas with ≥8% margin from all edges; strong mobile readability.',
    ],
  },
  {
    id: 'instagram_story',
    name: 'Instagram story',
    category: 'social',
    width: 1080,
    height: 1920,
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    safeZone:
      '1080×1920 (9:16) story. Full-bleed vertical; keep text/CTAs in middle third — avoid top/bottom ~250px UI chrome.',
    overlayInsets: Object.freeze({ top: 0.13, right: 0.08, bottom: 0.13, left: 0.08 }),
    overlayAlign: 'middle',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Instagram STORY (9:16 tall).',
      'Continuous vertical full-bleed design — no empty solid bars at top or bottom.',
      'Keep headlines and CTAs in the MIDDLE vertical third.',
      'Avoid top ~250px and bottom ~250px (system UI / reply chrome).',
      'Left/right margins ≥8% for all text.',
    ],
  },
  {
    id: 'instagram_landscape',
    name: 'Instagram landscape',
    category: 'social',
    width: 1080,
    height: 566,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1080×566 (~1.91:1) landscape feed. Full-bleed; center subject + text with ≥10% margins.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Instagram LANDSCAPE feed (~1.91:1).',
      'Wide continuous scene; center focal subject and typography.',
      'Text ≥10% from edges; no empty side or top/bottom bars.',
    ],
  },
  {
    id: 'facebook_post',
    name: 'Facebook post',
    category: 'social',
    width: 1200,
    height: 630,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1200×630 (~1.91:1) link/post preview. Full-bleed; large centered high-contrast text with ≥10% margins.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Facebook POST / link preview (~1.91:1).',
      'Designed to stay clear when shrunk in News Feed.',
      'Large centered headline, high contrast; ≥10% margins; no cluttered tiny type.',
    ],
  },
  {
    id: 'facebook_cover',
    name: 'Facebook cover',
    category: 'social',
    width: 820,
    height: 312,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '820×312 (~2.63:1) page/profile cover. Full-bleed across width; text in center band; keep lower-left quieter for profile UI.',
    overlayInsets: Object.freeze({ top: 0.08, right: 0.08, bottom: 0.08, left: 0.12 }),
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'Facebook COVER photo (~2.63:1 panoramic).',
      'Texture and design must span FULL WIDTH — no empty side panels.',
      'Keep primary text in the horizontal CENTER band with ≥12% side margins.',
      'Lower-LEFT should stay quieter (profile picture / UI overlap on some layouts).',
      'Critical content in vertical center (source will be cover-cropped to this strip).',
    ],
  },
  {
    id: 'x_post',
    name: 'X / Twitter post',
    category: 'social',
    width: 1600,
    height: 900,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1600×900 (16:9) timeline image. Full-bleed; strong center focus; text ≥10% from edges.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'X / Twitter POST image (16:9).',
      'Cinematic landscape fill; strong center focus.',
      'Headline fully visible with ≥10% margins; readable in timeline.',
    ],
  },
  {
    id: 'x_header',
    name: 'X / Twitter header',
    category: 'social',
    width: 1500,
    height: 500,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1500×500 (3:1) profile header. Full-bleed; text upper/center; leave lower-center clear for avatar overlap.',
    overlayInsets: Object.freeze({ top: 0.08, right: 0.1, bottom: 0.18, left: 0.1 }),
    overlayAlign: 'center',
    recommendedTextMode: 'overlay',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'X / Twitter PROFILE HEADER (3:1 panoramic).',
      'Continuous design across FULL WIDTH — no empty side bars.',
      'Place text in the UPPER / CENTER safe band.',
      'Leave LOWER-CENTER relatively clear for circular avatar overlap on the profile page.',
      'Keep left/right extremes free of critical text; ≥10% side margins.',
    ],
  },
  {
    id: 'youtube_thumbnail',
    name: 'YouTube thumbnail',
    category: 'social',
    width: 1280,
    height: 720,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone:
      '1280×720 (16:9) thumbnail. Full-bleed; huge high-contrast title; ≥10% margins; readable at small size.',
    overlayInsets: INSET_10,
    overlayAlign: 'center',
    recommendedTextMode: 'baked',
    composeRules: [
      ...FULL_BLEED_COMMON,
      'YouTube THUMBNAIL (16:9).',
      'Bold, high-contrast, clickable composition that fills the frame.',
      'Title text LARGE and fully on-canvas (≥10% margins); must stay legible at small thumbnail size.',
      'Avoid tiny details that disappear when scaled down; no empty bars.',
    ],
  },
]);

const FORMAT_BY_ID = Object.freeze(
  Object.fromEntries(FORMATS.map((f) => [f.id, f]))
);

function listFormats() {
  return FORMATS.map((f) => ({
    id: f.id,
    name: f.name,
    category: f.category,
    width: f.width,
    height: f.height,
    safeZone: f.safeZone,
    overlayInsets: f.overlayInsets || null,
    overlayAlign: f.overlayAlign || null,
    recommendedTextMode: f.recommendedTextMode || null,
  }));
}

function resolveFormat(formatId) {
  if (!formatId) return null;
  return FORMAT_BY_ID[formatId] || null;
}

function openaiSizeForFormat(format, openaiModel) {
  if (!format) {
    return String(openaiModel || '').startsWith('dall-e') ? '1024x1024' : '1024x1024';
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
