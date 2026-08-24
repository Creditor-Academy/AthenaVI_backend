/**
 * Build a Google Fonts CSS2 stylesheet URL for one or more families.
 * Shared by brand-kit PDF, fonts catalog API, and Remotion.
 */

function googleFontsHref(families, { weights } = {}) {
  const unique = [
    ...new Set(
      (Array.isArray(families) ? families : [families])
        .map((f) => String(f || '').trim())
        .filter(Boolean)
    ),
  ];
  if (!unique.length) return null;

  const weightSpec = weights || '300;400;500;600;700;800';
  const query = unique
    .map(
      (f) =>
        `family=${encodeURIComponent(f).replace(/%20/g, '+')}:wght@${weightSpec}`
    )
    .join('&');
  return `https://fonts.googleapis.com/css2?${query}&display=swap`;
}

/**
 * Derive a stylesheet URL from themeTokens.fonts (heading / subheading / body / tertiary).
 */
function fontCssUrlFromThemeTokens(themeTokens) {
  const fonts = themeTokens?.fonts || {};
  return googleFontsHref([
    fonts.heading,
    fonts.subheading,
    fonts.body,
    fonts.tertiary,
  ]);
}

module.exports = {
  googleFontsHref,
  fontCssUrlFromThemeTokens,
};
