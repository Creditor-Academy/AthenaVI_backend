const path = require('path');
const AppError = require('../../shared/utils/AppError');

const catalog = require('./themes/catalog.json');

const DEFAULT_THEME_ID = 'midnight_blue';
const AA_CONTRAST_RATIO = 4.5;

function listThemes() {
  return catalog.map((theme) => ({
    id: theme.id,
    name: theme.name,
    themeTokens: theme.themeTokens,
  }));
}

function getThemeById(id) {
  const themeId = String(id || '').trim();
  if (!themeId) return null;
  return catalog.find((theme) => theme.id === themeId) || null;
}

function parseHexColor(hex) {
  const raw = String(hex || '')
    .trim()
    .replace(/^#/, '');
  if (!/^[0-9a-fA-F]{6}$/.test(raw) && !/^[0-9a-fA-F]{3}$/.test(raw)) {
    return null;
  }
  const full =
    raw.length === 3
      ? raw
          .split('')
          .map((ch) => ch + ch)
          .join('')
      : raw;
  return {
    r: parseInt(full.slice(0, 2), 16),
    g: parseInt(full.slice(2, 4), 16),
    b: parseInt(full.slice(4, 6), 16),
  };
}

function srgbChannelToLinear(channel8) {
  const c = channel8 / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance(hex) {
  const rgb = parseHexColor(hex);
  if (!rgb) return null;
  const r = srgbChannelToLinear(rgb.r);
  const g = srgbChannelToLinear(rgb.g);
  const b = srgbChannelToLinear(rgb.b);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(hexA, hexB) {
  const l1 = relativeLuminance(hexA);
  const l2 = relativeLuminance(hexB);
  if (l1 == null || l2 == null) return null;
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * WCAG AA check for text vs background (4.5:1).
 * @param {{ bg?: string, text?: string }} palette
 */
function assertContrast(palette) {
  if (!palette || typeof palette !== 'object') {
    throw new AppError('Theme palette is required for contrast check', 400);
  }

  const { bg, text } = palette;
  if (!bg || !text) {
    throw new AppError('Theme palette must include bg and text colors', 400);
  }

  const textRatio = contrastRatio(text, bg);
  if (textRatio == null) {
    throw new AppError('Theme palette colors must be valid hex values', 400);
  }
  if (textRatio < AA_CONTRAST_RATIO) {
    throw new AppError(
      `Theme text/bg contrast ${textRatio.toFixed(2)}:1 fails WCAG AA (need ${AA_CONTRAST_RATIO}:1)`,
      400
    );
  }

  return true;
}

/**
 * Resolve curated themeId and/or custom themeTokens; contrast-checks result.
 * @param {{ themeId?: string|null, themeTokens?: object|null }} input
 * @returns {object} themeTokens
 */
function resolveThemeTokens({ themeId, themeTokens } = {}) {
  const hasCustom = themeTokens != null && typeof themeTokens === 'object';
  const id = themeId != null && String(themeId).trim() !== '' ? String(themeId).trim() : null;

  let resolved;
  if (hasCustom) {
    resolved = themeTokens;
  } else if (id) {
    const theme = getThemeById(id);
    if (!theme) {
      throw new AppError(`Unknown themeId: ${id}`, 400);
    }
    resolved = theme.themeTokens;
  } else {
    const fallback = getThemeById(DEFAULT_THEME_ID);
    if (!fallback) {
      throw new AppError(`Default theme missing: ${DEFAULT_THEME_ID}`, 500);
    }
    resolved = fallback.themeTokens;
  }

  if (!resolved?.palette) {
    throw new AppError('themeTokens.palette is required', 400);
  }

  assertContrast(resolved.palette);
  return resolved;
}

module.exports = {
  DEFAULT_THEME_ID,
  AA_CONTRAST_RATIO,
  listThemes,
  getThemeById,
  resolveThemeTokens,
  assertContrast,
  // path kept for tests / tooling that need the catalog file location
  catalogPath: path.join(__dirname, 'themes', 'catalog.json'),
};
