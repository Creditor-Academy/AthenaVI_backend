const AppError = require('../../shared/utils/AppError');
const { chatJson } = require('../../shared/services/ai/llm.service');
const { moderateText } = require('../../shared/services/ai/moderation.service');
const themeService = require('./theme.service');
const generationFlowService = require('./generationFlow.service');
const wizardColorThemes = require('./wizardColorThemes.json');

const PROMPT_SUGGESTED_ID = 'prompt_suggested';

const VIBE_PALETTE_SYSTEM = `You are a presentation design assistant. Given a deck topic and context, output a cohesive 5-color palette for slides.
Rules:
- Return valid #RRGGBB hex colors only.
- "appearance" is "light" or "dark" based on background luminance.
- "background" is slide base; "text" must meet WCAG AA contrast on background (4.5:1).
- Use ONE dominant hue family: primary, secondary, and accent must share the same base hue (analogous) or one controlled accent shift (±30°)—never unrelated rainbow primaries (e.g. pink + yellow + green together).
- "secondary" is a muted, low-saturation support tone (not a second loud brand color).
- "accent" is a single pop color derived from primary (slightly shifted hue or brighter), not a third unrelated hue.
- "name" is a short evocative palette title (2-4 words).`;

const VIBE_PALETTE_SCHEMA = {
  name: 'string',
  appearance: 'light | dark',
  background: '#RRGGBB',
  primary: '#RRGGBB',
  secondary: '#RRGGBB',
  accent: '#RRGGBB',
  text: '#RRGGBB',
  rationale: 'optional one sentence',
};

const HEX_RE = /^#[0-9A-Fa-f]{6}$/;

function normalizeHex(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const withHash = raw.startsWith('#') ? raw : `#${raw}`;
  if (!HEX_RE.test(withHash)) return null;
  return withHash.toUpperCase();
}

function hexToHsl(hex) {
  const rgb = themeService.parseHexColor(normalizeHex(hex) || '');
  if (!rgb) return null;
  const r = rgb.r / 255;
  const g = rgb.g / 255;
  const b = rgb.b / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  if (max === min) return { h: 0, s: 0, l };
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
  else if (max === g) h = ((b - r) / d + 2) / 6;
  else h = ((r - g) / d + 4) / 6;
  return { h: h * 360, s, l };
}

function hslToHex(h, s, l) {
  const hue = ((Number(h) % 360) + 360) % 360;
  const sat = Math.max(0, Math.min(1, Number(s)));
  const lit = Math.max(0, Math.min(1, Number(l)));
  const c = (1 - Math.abs(2 * lit - 1)) * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = lit - c / 2;
  let r = 0;
  let g = 0;
  let b = 0;
  if (hue < 60) {
    r = c;
    g = x;
  } else if (hue < 120) {
    r = x;
    g = c;
  } else if (hue < 180) {
    g = c;
    b = x;
  } else if (hue < 240) {
    g = x;
    b = c;
  } else if (hue < 300) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }
  const toHex = (n) => {
    const s = Math.round(Math.max(0, Math.min(255, n))).toString(16);
    return s.length === 1 ? `0${s}` : s;
  };
  return `#${toHex((r + m) * 255)}${toHex((g + m) * 255)}${toHex((b + m) * 255)}`.toUpperCase();
}

/**
 * Derive secondary/accent from primary so UI stripes stay one harmonious family.
 */
function harmonizeSuggestedPalette(data) {
  if (!data || typeof data !== 'object') return data;
  const primaryHex = normalizeHex(data.primary);
  const bgHex = normalizeHex(data.background);
  if (!primaryHex) return data;

  const primaryHsl = hexToHsl(primaryHex);
  if (!primaryHsl) return data;

  const accentH = (primaryHsl.h + 32) % 360;
  const secondaryHsl = {
    h: primaryHsl.h,
    s: Math.min(0.38, Math.max(0.12, primaryHsl.s * 0.45)),
    l: primaryHsl.l > 0.55 ? 0.62 : 0.42,
  };
  const accentHsl = {
    h: accentH,
    s: Math.min(0.72, Math.max(0.35, primaryHsl.s)),
    l: Math.min(0.58, Math.max(0.42, primaryHsl.l + 0.06)),
  };

  const secondaryHex = hslToHex(secondaryHsl.h, secondaryHsl.s, secondaryHsl.l);
  const accentHex = hslToHex(accentHsl.h, accentHsl.s, accentHsl.l);

  return {
    ...data,
    primary: primaryHex,
    secondary: secondaryHex,
    accent: accentHex,
    ...(bgHex ? { background: bgHex } : {}),
  };
}

function tokenizeForScore(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2);
}

function scoreCatalogTheme(prompt, tone, audience, purpose) {
  const blob = [prompt, tone, audience, purpose].filter(Boolean).join(' ');
  const words = tokenizeForScore(blob);
  if (!words.length) {
    return wizardColorThemes[0] || null;
  }

  let best = wizardColorThemes[0];
  let bestScore = -1;

  for (const theme of wizardColorThemes) {
    const hay = `${theme.name} ${theme.vibe || ''}`.toLowerCase();
    let score = 0;
    for (const word of words) {
      if (hay.includes(word)) score += 2;
      for (const part of (theme.vibe || '').split('/')) {
        const token = part.trim();
        if (token && token.includes(word)) score += 1;
      }
    }
    if (score > bestScore) {
      bestScore = score;
      best = theme;
    }
  }
  return best;
}

function buildThemeTokensFromRoles({ background, primary, secondary, accent, text, appearance, name, vibeLabel }) {
  const bg = normalizeHex(background);
  const surface = bg;
  const primaryHex = normalizeHex(primary);
  const secondaryHex = normalizeHex(secondary);
  const accentHex = normalizeHex(accent);
  let textHex = normalizeHex(text);

  if (!bg || !primaryHex || !secondaryHex || !accentHex || !textHex) {
    throw new AppError('Invalid palette hex values', 400);
  }

  let resolvedAppearance =
    appearance === 'dark' || appearance === 'light'
      ? appearance
      : themeService.appearanceFromBg(bg);

  const safeInk = themeService.SAFE_INK_BY_APPEARANCE[resolvedAppearance] || themeService.SAFE_INK_BY_APPEARANCE.light;
  if (themeService.contrastRatio(textHex, bg) < themeService.AA_CONTRAST_RATIO) {
    textHex = normalizeHex(safeInk.text) || textHex;
  }

  const muted = themeService.contrastRatio(secondaryHex, bg) >= 3 ? secondaryHex : safeInk.muted;

  let themeTokens = {
    appearance: resolvedAppearance,
    palette: {
      bg,
      surface,
      cardBg: surface,
      primary: primaryHex,
      secondary: secondaryHex,
      text: textHex,
      muted,
      heading: textHex,
      body: muted,
      accent: accentHex,
      border: resolvedAppearance === 'dark' ? 'rgba(255,255,255,0.12)' : '#E2E8F0',
      overlayScrim: 'rgba(0,0,0,0.5)',
      textOnImage: '#FFFFFF',
      textOnImageMuted: 'rgba(255,255,255,0.85)',
    },
    wizardColorThemeId: PROMPT_SUGGESTED_ID,
    colorTreatment: `${vibeLabel || name || 'custom'}; primary ${primaryHex}, accent ${accentHex}`,
    fontSource: 'wizard',
  };

  themeTokens = themeService.enforceAppearancePalette(themeTokens);
  themeService.assertContrast(themeTokens.palette);
  return themeTokens;
}

function responseFromCatalogFallback(theme, prompt) {
  const wizardTokens = generationFlowService.resolveWizardThemeTokens(theme.id, null, null);
  if (!wizardTokens?.palette) {
    throw new AppError('Catalog theme tokens missing', 500);
  }

  const colors = [
    theme.primary,
    theme.background,
    theme.secondary,
    theme.accent,
    theme.textPrimary,
  ].map((c) => normalizeHex(c) || c);

  return {
    id: theme.id,
    catalogThemeId: theme.id,
    fallback: true,
    name: theme.name,
    subtitle: 'Matched from catalog',
    appearance: theme.appearance || themeService.appearanceFromBg(theme.background),
    colors,
    themeTokens: {
      ...wizardTokens,
      appearance: theme.appearance || themeService.appearanceFromBg(theme.background),
      fontSource: 'wizard',
    },
    rationale: prompt ? `Closest catalog palette for your topic.` : '',
  };
}

function responseFromCustom(data) {
  const themeTokens = buildThemeTokensFromRoles({
    background: data.background,
    primary: data.primary,
    secondary: data.secondary,
    accent: data.accent,
    text: data.text,
    appearance: data.appearance,
    name: data.name,
    vibeLabel: data.rationale,
  });

  const colors = [
    data.primary,
    data.background,
    data.secondary,
    data.accent,
    data.text,
  ].map((c) => normalizeHex(c) || c);

  return {
    id: PROMPT_SUGGESTED_ID,
    catalogThemeId: null,
    fallback: false,
    name: String(data.name || 'Custom palette').trim().slice(0, 80),
    subtitle: 'From your topic',
    appearance: themeTokens.appearance,
    colors,
    themeTokens,
    rationale: data.rationale ? String(data.rationale).trim().slice(0, 300) : '',
  };
}

function validateLlmPalette(data) {
  if (!data || typeof data !== 'object') {
    throw new AppError('AI returned invalid palette shape', 502);
  }
  const fields = ['background', 'primary', 'secondary', 'accent', 'text'];
  for (const key of fields) {
    if (!normalizeHex(data[key])) {
      throw new AppError(`AI palette missing valid ${key}`, 502);
    }
  }
  if (!String(data.name || '').trim()) {
    data.name = 'Custom palette';
  }
}

async function suggestVibePalette({ prompt, tone, audience, purpose }) {
  const trimmed = String(prompt || '').trim();
  if (!trimmed) {
    throw new AppError('prompt is required', 400);
  }

  await moderateText(trimmed);
  if (tone) await moderateText(tone);
  if (audience) await moderateText(audience);
  if (purpose) await moderateText(purpose);

  const userLines = [
    `Deck topic / prompt:\n${trimmed.slice(0, 4000)}`,
    tone ? `Tone: ${tone}` : null,
    audience ? `Audience: ${audience}` : null,
    purpose ? `Purpose: ${purpose}` : null,
  ]
    .filter(Boolean)
    .join('\n\n');

  try {
    const { data } = await chatJson({
      system: VIBE_PALETTE_SYSTEM,
      user: userLines,
      schemaHint: VIBE_PALETTE_SCHEMA,
      temperature: 0.45,
    });
    validateLlmPalette(data);
    return responseFromCustom(harmonizeSuggestedPalette(data));
  } catch (err) {
    const catalogTheme = scoreCatalogTheme(trimmed, tone, audience, purpose);
    if (!catalogTheme) {
      throw err;
    }
    return responseFromCatalogFallback(catalogTheme, trimmed);
  }
}

module.exports = {
  PROMPT_SUGGESTED_ID,
  suggestVibePalette,
  buildThemeTokensFromRoles,
  scoreCatalogTheme,
  normalizeHex,
  harmonizeSuggestedPalette,
  hexToHsl,
};
