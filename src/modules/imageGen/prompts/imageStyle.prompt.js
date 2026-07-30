const { styleSuffix } = require('../catalogs/styles');

function buildImagePrompt({ prompt, styleId }) {
  const parts = [String(prompt || '').trim()];
  const suffix = styleSuffix(styleId);
  if (suffix) {
    parts.push(suffix);
  }
  return parts.filter(Boolean).join('\n\n');
}

module.exports = {
  buildImagePrompt,
};
