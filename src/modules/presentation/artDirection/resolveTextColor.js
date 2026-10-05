const {
  contrastRatioCss,
  relativeLuminance,
  safeInkForAppearance,
  appearanceFromSurfaceHex,
} = require('../theme.service');

function highContrastFallback(backgroundHex) {
  const surface = appearanceFromSurfaceHex(backgroundHex);
  const ink = safeInkForAppearance(surface === 'dark' ? 'dark' : 'light');
  return { colorRole: 'text', color: ink.text };
}

function resolveTextColor({ theme, textRole, backgroundMode = 'light', backgroundHex, _depth = 0 } = {}) {
  const palette = theme?.palette || {};
  const surfaceAppearance =
    backgroundHex != null ? appearanceFromSurfaceHex(backgroundHex) : null;
  const surfaceInk =
    surfaceAppearance != null ? safeInkForAppearance(surfaceAppearance) : null;

  const safeHeadingColor =
    (surfaceInk && surfaceInk.heading) ||
    palette.heading ||
    palette.text ||
    palette.body ||
    '#18212B';
  const safeBodyColor =
    (surfaceInk && surfaceInk.muted) ||
    palette.body ||
    palette.muted ||
    palette.text ||
    '#52606D';

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
      color = safeBodyColor;
      colorRole = 'muted';
    }
  } else {
    // heading/display
    if (useOnImage && palette.textOnImage) {
      color = palette.textOnImage;
      colorRole = 'textOnImage';
    } else {
      color = safeHeadingColor;
      colorRole = 'text';
    }
  }

  // Optional readability guard: if we can compute ratio and it's too low,
  // fall back to heading/body tokens.
  if (backgroundHex) {
    const ratio = contrastRatioCss(color, backgroundHex);
    if (ratio != null && ratio < 4.5) {
      if (_depth >= 1) {
        return highContrastFallback(backgroundHex);
      }
      if (colorRole === 'muted' || colorRole === 'textonimagemuted') {
        return resolveTextColor({
          theme,
          textRole: 'heading',
          backgroundMode,
          backgroundHex,
          _depth: _depth + 1,
        });
      }
      if (colorRole === 'text' || colorRole === 'textonimage') {
        return resolveTextColor({
          theme,
          textRole: 'body',
          backgroundMode,
          backgroundHex,
          _depth: _depth + 1,
        });
      }
      return highContrastFallback(backgroundHex);
    }
  }

  return { colorRole, color };
}

module.exports = {
  resolveTextColor,
};
