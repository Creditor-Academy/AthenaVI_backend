const path = require('path');
const AppError = require('../../shared/utils/AppError');

const catalog = require('./themes/catalog.json');

const DEFAULT_THEME_ID = 'midnight_blue';
const AA_CONTRAST_RATIO = 4.5;

const APPEARANCE_LUM_THRESHOLD = 0.35;
const SAFE_BG_BY_APPEARANCE = {
  light: { bg: '#FFFFFF', surface: '#F8FAFC', gradientStart: '#FFFFFF', gradientEnd: '#F8FAFC' },
  dark: { bg: '#0B1220', surface: '#121A2B', gradientStart: '#0B1220', gradientEnd: '#121A2B' },
};

function listThemes() {
  return catalog.map((theme) => ({
    id: theme.id,
    name: theme.name,
    appearance: theme.themeTokens?.appearance || appearanceFromBg(theme.themeTokens?.palette?.bg),
    themeTokens: theme.themeTokens,
  }));
}

function appearanceFromBg(hex) {
  const lum = relativeLuminance(hex);
  if (lum == null) return 'light';
  return lum < APPEARANCE_LUM_THRESHOLD ? 'dark' : 'light';
}

function luminanceMatchesAppearance(hex, appearance) {
  const lum = relativeLuminance(hex);
  if (lum == null) return true;
  if (appearance === 'dark') return lum < APPEARANCE_LUM_THRESHOLD;
  return lum >= APPEARANCE_LUM_THRESHOLD;
}

/**
 * Ensure palette bg/surface/gradients match declared appearance (light never uses dark bg).
 */
function enforceAppearancePalette(themeTokens) {
  if (!themeTokens?.palette || typeof themeTokens.palette !== 'object') return themeTokens;
  const palette = { ...themeTokens.palette };
  const appearance =
    themeTokens.appearance === 'dark' || themeTokens.appearance === 'light'
      ? themeTokens.appearance
      : appearanceFromBg(palette.bg);
  const safe = SAFE_BG_BY_APPEARANCE[appearance] || SAFE_BG_BY_APPEARANCE.light;

  for (const key of ['bg', 'surface', 'gradientStart', 'gradientEnd']) {
    if (palette[key] && !luminanceMatchesAppearance(palette[key], appearance)) {
      palette[key] = safe[key] || safe.bg;
    }
  }
  if (!palette.gradientStart) palette.gradientStart = palette.bg || safe.bg;
  if (!palette.gradientEnd) palette.gradientEnd = palette.surface || safe.surface;

  return { ...themeTokens, appearance, palette };
}

/** Map wizard / FE PDF theme ids onto catalog or wizard-derived tokens later. */
const THEME_ID_ALIASES = {
  modern_professional: 'soft-sky',
  'modern-professional': 'soft-sky',
  midnight_dark: 'deep-space',
  'midnight-dark': 'deep-space',
  soft_sky: 'soft-sky',
  pastel_dream: 'pastel-dream',
  nature_fresh: 'nature-fresh',
  ocean_breeze: 'ocean-breeze',
  urban_cool: 'urban-cool',
  warm_embrace: 'warm-embrace',
  deep_space: 'deep-space',
  modern_dark: 'modern-dark',
  tech_noir: 'tech-noir',
  sunset_dark: 'sunset-dark',
  forest_night: 'forest-night',
  ocean_deep: 'ocean-deep',
  luxe_dark: 'luxe-dark',
  elegant_dark: 'elegant-dark',
  // legacy catalog aliases
  clean_light: 'soft-sky',
  midnight_blue: 'deep-space',
  earthy_sage: 'nature-fresh',
  'earthy-sage': 'nature-fresh',
  'ocean-breeze': 'ocean-breeze',
  vintage_paper: 'ethereal',
  'vintage-paper': 'ethereal',
};

function resolveWizardThemeTokens(themeId) {
  try {
    const generationFlowService = require('./generationFlow.service');
    const raw = String(themeId || '').trim();
    if (!raw) return null;
    const candidates = [raw, raw.replace(/_/g, '-'), raw.replace(/-/g, '_')];
    for (const id of candidates) {
      const wizardTokens = generationFlowService.resolveWizardThemeTokens(id, null, null);
      if (wizardTokens?.palette) return wizardTokens;
    }
  } catch {
    return null;
  }
  return null;
}

function normalizeThemeId(id) {
  const raw = String(id || '').trim();
  if (!raw) return '';
  if (THEME_ID_ALIASES[raw]) return THEME_ID_ALIASES[raw];
  const underscored = raw.replace(/-/g, '_');
  if (THEME_ID_ALIASES[underscored]) return THEME_ID_ALIASES[underscored];
  return raw;
}

function getThemeById(id) {
  const themeId = normalizeThemeId(id);
  if (!themeId) return null;
  return (
    catalog.find((theme) => theme.id === themeId) ||
    catalog.find((theme) => theme.id === String(id || '').trim()) ||
    null
  );
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

function parseCssColor(color) {
  const raw = String(color || '').trim();
  if (!raw) return null;

  // #RRGGBB / #RGB
  const hex = raw.startsWith('#') ? raw : raw.match(/^[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/) ? raw : null;
  if (hex) {
    const rgb = parseHexColor(hex.startsWith('#') ? hex : `#${hex}`);
    if (!rgb) return null;
    return { r: rgb.r, g: rgb.g, b: rgb.b, a: 1 };
  }

  // rgb(r,g,b)
  const rgbMatch = raw.match(/^rgb\s*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/i);
  if (rgbMatch) {
    return {
      r: Math.max(0, Math.min(255, Number(rgbMatch[1]))),
      g: Math.max(0, Math.min(255, Number(rgbMatch[2]))),
      b: Math.max(0, Math.min(255, Number(rgbMatch[3]))),
      a: 1,
    };
  }

  // rgba(r,g,b,a) where a in [0..1]
  const rgbaMatch = raw.match(
    /^rgba\s*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*([01]?\.?\d+)\s*\)$/i
  );
  if (rgbaMatch) {
    return {
      r: Math.max(0, Math.min(255, Number(rgbaMatch[1]))),
      g: Math.max(0, Math.min(255, Number(rgbaMatch[2]))),
      b: Math.max(0, Math.min(255, Number(rgbaMatch[3]))),
      a: Math.max(0, Math.min(1, Number(rgbaMatch[4]))),
    };
  }

  return null;
}

function rgbaToHex({ r, g, b }) {
  const to = (n) => {
    const s = Math.round(Math.max(0, Math.min(255, Number(n)))).toString(16);
    return s.length === 1 ? `0${s}` : s;
  };
  return `#${to(r)}${to(g)}${to(b)}`;
}

function compositeRgbaOnHex(fgRgba, bgHex) {
  const bgRgb = parseHexColor(bgHex);
  if (!bgRgb) return rgbaToHex({ r: fgRgba.r, g: fgRgba.g, b: fgRgba.b });
  const a = fgRgba.a == null ? 1 : fgRgba.a;
  if (a >= 1) return rgbaToHex({ r: fgRgba.r, g: fgRgba.g, b: fgRgba.b });
  const r = a * fgRgba.r + (1 - a) * bgRgb.r;
  const g = a * fgRgba.g + (1 - a) * bgRgb.g;
  const b = a * fgRgba.b + (1 - a) * bgRgb.b;
  return rgbaToHex({ r, g, b });
}

function contrastRatioCss(fgCss, bgCss) {
  // fgCss/bgCss can be hex or rgba(...) for token-based palettes.
  const fg = parseCssColor(fgCss);
  const bg = parseCssColor(bgCss);
  if (!fg || !bg) return null;

  const bgHex = rgbaToHex(bg);
  const bgOpaqueHex = compositeRgbaOnHex(bg, '#FFFFFF');
  const bgForRatio = bg.a != null && bg.a < 1 ? bgOpaqueHex : bgHex;

  const fgHex = fg.a != null && fg.a < 1 ? compositeRgbaOnHex(fg, bgForRatio) : rgbaToHex(fg);
  return contrastRatio(fgHex, bgForRatio);
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
  const id = themeId != null && String(themeId).trim() !== '' ? normalizeThemeId(themeId) : null;

  let resolved;
  if (hasCustom) {
    resolved = themeTokens;
  } else if (id || (themeId != null && String(themeId).trim() !== '')) {
    const theme = getThemeById(themeId);
    if (!theme) {
      const wizardTokens = resolveWizardThemeTokens(themeId);
      if (wizardTokens?.palette) {
        resolved = wizardTokens;
      } else {
        throw new AppError(`Unknown themeId: ${themeId}`, 400);
      }
    } else {
      resolved = theme.themeTokens;
    }
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

  resolved = enforceAppearancePalette(resolved);
  assertContrast(resolved.palette);

  if (id || (themeId != null && String(themeId).trim() !== '' && getThemeById(themeId))) {
    return { ...resolved, fontSource: resolved.fontSource || 'catalog' };
  }

  return resolved;
}

module.exports = {
  DEFAULT_THEME_ID,
  AA_CONTRAST_RATIO,
  APPEARANCE_LUM_THRESHOLD,
  THEME_ID_ALIASES,
  normalizeThemeId,
  listThemes,
  getThemeById,
  resolveThemeTokens,
  enforceAppearancePalette,
  appearanceFromBg,
  assertContrast,
  contrastRatio,
  relativeLuminance,
  parseHexColor,
  parseCssColor,
  contrastRatioCss,
  // path kept for tests / tooling that need the catalog file location
  catalogPath: path.join(__dirname, 'themes', 'catalog.json'),
};
