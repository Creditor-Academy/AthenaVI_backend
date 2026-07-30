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
    safeZone: 'Keep subject centered.',
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
    safeZone: 'Ultra-wide cover — keep faces and logo away from edges; leave room for profile crop.',
  },
  {
    id: 'linkedin_post',
    name: 'LinkedIn post',
    category: 'social',
    width: 1200,
    height: 627,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Center the hero subject; avoid critical text near edges.',
  },
  {
    id: 'instagram_post',
    name: 'Instagram post',
    category: 'social',
    width: 1080,
    height: 1080,
    openaiSizeGpt: '1024x1024',
    openaiSizeDalle: '1024x1024',
    safeZone: 'Square feed post — bold centered composition.',
  },
  {
    id: 'instagram_story',
    name: 'Instagram story',
    category: 'social',
    width: 1080,
    height: 1920,
    openaiSizeGpt: '1024x1536',
    openaiSizeDalle: '1024x1792',
    safeZone: 'Keep important content away from top/bottom UI chrome (~250px).',
  },
  {
    id: 'instagram_landscape',
    name: 'Instagram landscape',
    category: 'social',
    width: 1080,
    height: 566,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Wide feed image — center focal subject.',
  },
  {
    id: 'facebook_post',
    name: 'Facebook post',
    category: 'social',
    width: 1200,
    height: 630,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Link-preview friendly; keep text large and centered.',
  },
  {
    id: 'facebook_cover',
    name: 'Facebook cover',
    category: 'social',
    width: 820,
    height: 312,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Ultra-wide cover — avoid critical content at far edges.',
  },
  {
    id: 'x_post',
    name: 'X / Twitter post',
    category: 'social',
    width: 1600,
    height: 900,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: '16:9 post image — strong center focus.',
  },
  {
    id: 'x_header',
    name: 'X / Twitter header',
    category: 'social',
    width: 1500,
    height: 500,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Wide header — leave center clear for avatar overlap on profile.',
  },
  {
    id: 'youtube_thumbnail',
    name: 'YouTube thumbnail',
    category: 'social',
    width: 1280,
    height: 720,
    openaiSizeGpt: '1536x1024',
    openaiSizeDalle: '1792x1024',
    safeZone: 'Bold high-contrast composition; leave space for large title text.',
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
