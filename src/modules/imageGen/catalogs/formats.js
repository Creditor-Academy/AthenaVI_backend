/**
 * Social + generic format catalog.
 * openaiSizeGpt / openaiSizeDalle = nearest API size; target WxH for sharp crop.
 */

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
      'Ultra-wide 4:1 banner. Keep ALL text and logos inside the middle horizontal band with ≥12% margin from top/bottom/left/right. Leave room for profile photo overlap on the left.',
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
      'Landscape ~1.91:1. Center hero + text; keep all copy inside ≥10% margins — no edge text.',
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
      '1:1 square. Bold centered composition; keep text fully inside with ≥8% margin from all edges.',
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
      '9:16 story. Keep text/CTAs in the vertical middle third — avoid top ~250px and bottom ~250px (UI chrome).',
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
      'Wide ~1.91:1 feed image. Center focal subject and text; ≥10% edge margins.',
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
      'Link-preview ~1.91:1. Large centered text fully inside ≥10% margins; high contrast.',
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
      'Ultra-wide cover. Keep all text in the center band with ≥12% margins; avoid far left/right edges.',
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
      '16:9 post. Strong center focus; all text fully visible with ≥10% margins.',
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
      'Wide 3:1 header. Keep text in the upper/center safe band; leave lower-center clear for avatar overlap.',
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
      '16:9 thumbnail. Large high-contrast title fully on-canvas with ≥10% margins; bold readable type.',
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
  }));
}

function resolveFormat(formatId) {
  if (!formatId) return null;
  return FORMAT_BY_ID[formatId] || null;
}

function openaiSizeForFormat(format) {
  if (!format) {
    return '1024x1024';
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
