const { contrastRatioCss } = require('../theme.service');

function resolveTextColor({ theme, textRole, backgroundMode = 'light', backgroundHex } = {}) {
  const palette = theme?.palette || {};
  const safeHeadingColor = palette.heading || palette.text || palette.body || '#18212B';
  const safeBodyColor = palette.body || palette.muted || palette.text || '#52606D';

  const mode = String(backgroundMode || '').toLowerCase();
  const useOnImage = mode === 'image' || mode === 'on_image' || mode === 'text_on_image';

  let color;
  let colorRole;

  if (textRole === 'accent') {
    color = palette.accent || palette.secondary || palette.primary || safeHeadingColor;
    colorRole = 'accent';
  } else if (textRole === 'secondary') {
    color = palette.secondary || palette.accent || palette.primary || safeHeadingColor;
    colorRole = 'secondary';
  } else if (textRole === 'primary') {
    color = palette.primary || safeHeadingColor;
    colorRole = 'primary';
  } else if (textRole === 'body' || textRole === 'muted') {
    if (useOnImage && palette.textOnImageMuted) {
      color = palette.textOnImageMuted;
      colorRole = 'textOnImageMuted';
    } else {
      color = palette.body || palette.muted || safeBodyColor;
      colorRole = 'muted';
    }
  } else {
    // heading/display
    if (useOnImage && palette.textOnImage) {
      color = palette.textOnImage;
      colorRole = 'textOnImage';
    } else {
      color = palette.heading || palette.text || safeHeadingColor;
      colorRole = 'text';
    }
  }

  // Optional readability guard: if we can compute ratio and it's too low,
  // fall back to heading/body tokens.
  if (backgroundHex) {
    const ratio = contrastRatioCss(color, backgroundHex);
    if (ratio != null && ratio < 4.5) {
      if (colorRole === 'muted' || colorRole === 'textonimagemuted') {
        return resolveTextColor({
          theme,
          textRole: 'heading',
          backgroundMode,
          backgroundHex,
        });
      }
      if (colorRole === 'text' || colorRole === 'textonimage') {
        return resolveTextColor({
          theme,
          textRole: 'body',
          backgroundMode,
          backgroundHex,
        });
      }
    }
  }

  return { colorRole, color };
}

module.exports = {
  resolveTextColor,
};

