const { resolveStickyBrandColors } = require('./semanticTheme');

function coverDesignTokens(themeTokens = {}) {
  const { appearance } = resolveStickyBrandColors(themeTokens);
  const overlayOpacity =
    themeTokens?.overlayDefaults?.overlayOpacity ?? (appearance === 'light' ? 0.4 : 0.45);
  return {
    backgroundStyle: 'image',
    overlayOpacity,
    textContrast: 'high',
  };
}

module.exports = {
  coverDesignTokens,
};
