const { appearanceFromBg } = require('../theme.service');

function resolveSemanticTheme(themeTokens = {}) {
  const palette = themeTokens?.palette || {};

  const background =
    palette.background || palette.bg || palette.bgColor || '#F7F5F0';
  const surface = palette.surface || palette.cardBg || palette.backgroundSecondary || background;

  const heading = palette.heading || palette.text || '#18212B';
  const body = palette.body || palette.muted || palette.text || '#52606D';
  const muted = palette.muted || palette.text || body;

  const brand = resolveStickyBrandColors(themeTokens);

  return {
    palette,
    themeTokens,
    colors: {
      background,
      surface,
      primary: brand.primary,
      secondary: brand.secondary,
      accent: brand.accent,
      heading,
      body,
      muted,
      border: palette.border || palette.divider,

      // Semantic names for dark surfaces (same tokens in this catalog-driven approach).
      darkBackground: palette.bg || background,
      darkSurface: surface,
      darkHeading: heading,
      darkBody: body,
    },
    appearance: brand.appearance,
  };
}

/**
 * Sticky brand identity for a deck: primary + secondary stay consistent across slides.
 */
function resolveStickyBrandColors(themeTokens = {}) {
  const safe = themeTokens && typeof themeTokens === 'object' ? themeTokens : {};
  const palette = safe.palette || {};
  const appearance =
    safe.appearance === 'dark' || safe.appearance === 'light'
      ? safe.appearance
      : appearanceFromBg(palette.bg);

  const primary = palette.primary || palette.accent || '#2563EB';
  const secondary =
    palette.secondary ||
    (palette.accent && palette.accent !== primary ? palette.accent : null) ||
    primary;
  const accent = palette.accent || secondary || primary;

  return {
    primary,
    secondary,
    accent,
    appearance,
  };
}

module.exports = {
  resolveSemanticTheme,
  resolveStickyBrandColors,
};
