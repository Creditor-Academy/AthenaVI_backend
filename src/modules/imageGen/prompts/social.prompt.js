const { styleSuffix } = require('../catalogs/styles');

/**
 * Build a social creative prompt with format-aware composition hints.
 */
function buildSocialPrompt({
  prompt,
  styleId,
  format,
  headline,
  subheadline,
  brandPalette,
} = {}) {
  const parts = [];
  if (format) {
    parts.push(
      `Design a ${format.name} social graphic at approximately ${format.width}x${format.height} aspect.`,
      format.safeZone || ''
    );
  }

  if (headline) {
    parts.push(`Include large readable headline text: "${String(headline).trim()}".`);
  }
  if (subheadline) {
    parts.push(`Include supporting subheadline: "${String(subheadline).trim()}".`);
  }

  if (Array.isArray(brandPalette) && brandPalette.length) {
    parts.push(`Brand colors: ${brandPalette.join(', ')}.`);
  }

  if (prompt) {
    parts.push(String(prompt).trim());
  }

  const suffix = styleSuffix(styleId);
  if (suffix) {
    parts.push(suffix);
  }

  parts.push(
    'High quality marketing creative, sharp typography where text is requested, polished composition.'
  );

  return parts.filter(Boolean).join('\n\n');
}

module.exports = {
  buildSocialPrompt,
};
