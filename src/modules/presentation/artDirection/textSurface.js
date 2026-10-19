/**
 * Classify text backdrop for contrast (image overlay vs solid surfaces).
 */

const FULL_BLEED_TITLE_RE =
  /title_fullbleed|full_bg_image|fullbleed|closing_thank_you_fullbleed|statement_top|statement_bottom/i;
const SPLIT_HERO_TITLE_RE = /title_hero_|title_image_logo|title_fullbleed/i;

function layoutIdOf(layoutSchema) {
  return String(layoutSchema?.layout_id || layoutSchema?.layoutId || '').toLowerCase();
}

function isFullBleedImageTitleLayout(layoutSchema) {
  const layoutId = layoutIdOf(layoutSchema);
  if (FULL_BLEED_TITLE_RE.test(layoutId)) return true;
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((s) => String(s.id || '').toUpperCase() === 'BACKGROUND_IMAGE');
}

function isSplitHeroTitleLayout(layoutSchema) {
  return SPLIT_HERO_TITLE_RE.test(layoutIdOf(layoutSchema));
}

function slotOptedOutOfImageText(slot) {
  const ty = slot?.typography || {};
  const surface = String(ty.textSurface || ty.surface || '').toLowerCase();
  return surface === 'card' || surface === 'solid';
}

/**
 * @returns {'imageOverlay'|'solidLight'|'solidDark'|'card'}
 */
function resolveSlotTextSurface(slot, layoutSchema, designTokens = null, themeTokens = null) {
  if (slotOptedOutOfImageText(slot)) return 'card';

  const layoutId = layoutIdOf(layoutSchema);
  const ct = String(layoutSchema?.content_type || '').toLowerCase();
  const role = String(slot?.role || '').toLowerCase();
  const slotId = String(slot?.id || '').toUpperCase();

  if (
    designTokens?.backgroundStyle === 'image' ||
    designTokens?.textContrast === 'high' ||
    isFullBleedImageTitleLayout(layoutSchema) ||
    /full_bg|overlay/i.test(layoutId)
  ) {
    return 'imageOverlay';
  }

  if (ct === 'title' && isSplitHeroTitleLayout(layoutSchema)) {
    if (
      role === 'heading' ||
      role === 'subheading' ||
      /MAIN_TITLE|SUBTITLE|HEADLINE|TAGLINE/.test(slotId)
    ) {
      return 'imageOverlay';
    }
  }

  const palette = themeTokens?.palette || {};
  const bg = String(palette.bg || palette.background || '#ffffff');
  const lum = relativeLuminance(bg);
  if (lum < 0.45) return 'solidDark';
  return 'solidLight';
}

function relativeLuminance(hex) {
  const s = String(hex || '').replace('#', '').trim();
  if (s.length !== 6) return 1;
  const r = parseInt(s.slice(0, 2), 16) / 255;
  const g = parseInt(s.slice(2, 4), 16) / 255;
  const b = parseInt(s.slice(4, 6), 16) / 255;
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function needsOverlayScrim(layoutSchema, designTokens) {
  if (!isFullBleedImageTitleLayout(layoutSchema)) return false;
  if (/title_fullbleed_overlay|title_fullbleed_v1/i.test(layoutIdOf(layoutSchema))) {
    return String(layoutSchema?.layout_id || '').includes('overlay');
  }
  return (
    designTokens?.backgroundStyle === 'image' ||
    isFullBleedImageTitleLayout(layoutSchema)
  );
}

function isImageOverlaySurface(surface) {
  return surface === 'imageOverlay';
}

module.exports = {
  isFullBleedImageTitleLayout,
  isSplitHeroTitleLayout,
  resolveSlotTextSurface,
  needsOverlayScrim,
  isImageOverlaySurface,
  slotOptedOutOfImageText,
};
