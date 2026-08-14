const logger = require('../../shared/utils/logger');
const { chatJson } = require('../../shared/services/ai/llm.service');
const {
  FONT_PAIRING_CATALOG: BRAND_KIT_PAIRINGS,
  FONTS_SUGGEST_SYSTEM,
  FONTS_SUGGEST_SCHEMA,
} = require('../brandKit/brandKit.prompts');

/** Extended catalog aligned with themes/catalog.json fontPairingId values. */
const FONT_PAIRING_CATALOG = [
  ...BRAND_KIT_PAIRINGS,
  { id: 'nunito_inter', heading: 'Nunito', subheading: 'Nunito', body: 'Inter' },
  { id: 'libre_ibm', heading: 'Libre Baskerville', subheading: 'Libre Baskerville', body: 'IBM Plex Sans' },
];

const ALLOWED_GOOGLE_FONTS = new Set(
  [
    'Playfair Display',
    'Inter',
    'Plus Jakarta Sans',
    'Outfit',
    'Roboto',
    'Montserrat',
    'Open Sans',
    'Poppins',
    'Syne',
    'Space Grotesk',
    'Lora',
    'Merriweather',
    'DM Sans',
    'Cinzel',
    'Cormorant Garamond',
    'Oswald',
    'Raleway',
    'Ubuntu',
    'Fraunces',
    'Source Sans 3',
    'Manrope',
    'Nunito',
    'Libre Baskerville',
    'IBM Plex Sans',
    'Lato',
  ].map((f) => f.toLowerCase())
);

const VIBE_PAIRING_FALLBACKS = [
  { match: /histor|education|academic|museum|classic|heritage|story/i, id: 'libre_ibm' },
  { match: /editorial|luxury|elegant|fashion|premium/i, id: 'playfair_lato' },
  { match: /startup|tech|modern|innovation|saas|product/i, id: 'outfit_source' },
  { match: /friendly|warm|community|nonprofit|social/i, id: 'nunito_inter' },
  { match: /minimal|clean|corporate|professional|business|pitch/i, id: 'inter_source' },
  { match: /creative|bold|design|agency|marketing/i, id: 'space_grotesk' },
];

const PAIRING_BY_ID = Object.fromEntries(FONT_PAIRING_CATALOG.map((p) => [p.id, p]));

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function hasUsableFonts(themeTokens) {
  const fonts = themeTokens?.fonts || {};
  return isNonEmptyString(fonts.heading) && isNonEmptyString(fonts.body);
}

function shouldSkipAiFontPick(themeTokens, { brandKitId } = {}) {
  if (brandKitId || themeTokens?.brand?.brandKitId) return true;
  const source = themeTokens?.fontSource;
  if (source === 'brand_kit' || source === 'catalog' || source === 'ai') return true;
  return false;
}

function fontsFromPairingId(pairingId) {
  const pairing = PAIRING_BY_ID[String(pairingId || '').trim()];
  if (!pairing) return null;
  return {
    fontPairingId: pairing.id,
    fonts: {
      heading: pairing.heading,
      subheading: pairing.subheading || pairing.heading,
      body: pairing.body,
      headingWeight: 700,
      subheadingWeight: 600,
      bodyWeight: 400,
    },
  };
}

function isAllowedFontFamily(family) {
  if (!isNonEmptyString(family)) return false;
  return ALLOWED_GOOGLE_FONTS.has(String(family).trim().toLowerCase());
}

function normalizeAiFontRole(role, fallbackPairingId) {
  if (!role || typeof role !== 'object') return null;
  const family = role.family || role.heading || role.body;
  if (!isAllowedFontFamily(family)) return null;
  return {
    family: String(family).trim(),
    weight: role.weight ?? 400,
    fontPairingId: role.fontPairingId || fallbackPairingId || null,
  };
}

function fontsFromAiResponse(data) {
  const raw = data?.fonts;
  if (!raw || typeof raw !== 'object') return null;

  const pairingId =
    raw.heading?.fontPairingId ||
    raw.body?.fontPairingId ||
    raw.subheading?.fontPairingId ||
    null;

  const heading = normalizeAiFontRole(raw.heading, pairingId);
  const subheading = normalizeAiFontRole(raw.subheading, pairingId);
  const body = normalizeAiFontRole(raw.body, pairingId);

  if (!heading?.family || !body?.family) return null;

  return {
    fontPairingId: pairingId && PAIRING_BY_ID[pairingId] ? pairingId : null,
    fonts: {
      heading: heading.family,
      subheading: subheading?.family || heading.family,
      body: body.family,
      headingWeight: heading.weight ?? 700,
      subheadingWeight: subheading?.weight ?? 600,
      bodyWeight: body.weight ?? 400,
    },
    fontRationale: data?.rationale || null,
  };
}

function vibeFallbackPairingId(contextText = '') {
  const text = String(contextText || '');
  for (const rule of VIBE_PAIRING_FALLBACKS) {
    if (rule.match.test(text)) return rule.id;
  }
  return 'outfit_source';
}

function applyFontsToThemeTokens(themeTokens, fontPatch) {
  if (!fontPatch) return themeTokens || {};
  const base = themeTokens && typeof themeTokens === 'object' ? { ...themeTokens } : {};
  return {
    ...base,
    fontPairingId: fontPatch.fontPairingId || base.fontPairingId || null,
    fonts: {
      ...(base.fonts || {}),
      ...(fontPatch.fonts || {}),
    },
    fontSource: fontPatch.fontSource || base.fontSource || null,
    ...(fontPatch.fontRationale ? { fontRationale: fontPatch.fontRationale } : {}),
  };
}

/**
 * Merge wizard palette onto deck/brand tokens without wiping fonts.
 */
function mergeThemeTokensPreservingFonts(deckTokens, incomingTokens) {
  const deck = deckTokens && typeof deckTokens === 'object' ? deckTokens : {};
  const incoming = incomingTokens && typeof incomingTokens === 'object' ? incomingTokens : {};

  const deckHasFonts = hasUsableFonts(deck);
  const incomingHasFonts = hasUsableFonts(incoming);

  const preserveIncomingFonts =
    incomingHasFonts &&
    (incoming.fontSource === 'brand_kit' ||
      incoming.brand?.brandKitId ||
      !deckHasFonts);

  const fonts = preserveIncomingFonts
    ? { ...(deck.fonts || {}), ...(incoming.fonts || {}) }
    : deckHasFonts
      ? { ...(deck.fonts || {}) }
      : { ...(deck.fonts || {}), ...(incoming.fonts || {}) };

  return {
    ...deck,
    ...incoming,
    palette: {
      ...(deck.palette || {}),
      ...(incoming.palette || {}),
    },
    fonts,
    fontPairingId: incoming.fontPairingId || deck.fontPairingId || null,
    fontSource: incoming.fontSource || deck.fontSource || null,
    typeScale: incoming.typeScale || deck.typeScale || null,
    brand: incoming.brand || deck.brand || undefined,
    colorTreatment: incoming.colorTreatment ?? deck.colorTreatment ?? null,
    imageStyle: incoming.imageStyle || deck.imageStyle || null,
    wizardColorThemeId: incoming.wizardColorThemeId || deck.wizardColorThemeId || null,
  };
}

async function suggestFontsWithAi({
  prompt,
  wizardBrief,
  tone,
  audience,
  purpose,
  style,
  primaryHex,
  colorTreatment,
}) {
  const context = [
    prompt ? `Presentation topic: ${prompt}` : null,
    wizardBrief ? `Brief:\n${wizardBrief}` : null,
    tone ? `Tone: ${tone}` : null,
    audience ? `Audience: ${audience}` : null,
    purpose ? `Purpose: ${purpose}` : null,
    style ? `Visual style: ${style}` : null,
    primaryHex ? `Primary color: ${primaryHex}` : null,
    colorTreatment ? `Color treatment: ${colorTreatment}` : null,
    `Available pairings: ${FONT_PAIRING_CATALOG.map((p) => p.id).join(', ')}`,
    'Pick fonts that match the topic and tone. Prefer distinctive pairings over generic Inter-only defaults when appropriate.',
  ]
    .filter(Boolean)
    .join('\n');

  const { data } = await chatJson({
    system: FONTS_SUGGEST_SYSTEM,
    user: context,
    schemaHint: FONTS_SUGGEST_SCHEMA,
    temperature: 0.45,
  });

  return fontsFromAiResponse(data);
}

/**
 * Ensure themeTokens has heading/body Google Font families.
 * Brand kit and explicit catalog fonts are preserved; otherwise AI picks from prompt context.
 */
async function ensureThemeFonts(themeTokens, context = {}) {
  const tokens = themeTokens && typeof themeTokens === 'object' ? { ...themeTokens } : {};

  if (shouldSkipAiFontPick(tokens, context) && hasUsableFonts(tokens)) {
    return tokens;
  }

  if (hasUsableFonts(tokens) && tokens.fontSource === 'ai') {
    return tokens;
  }

  const pairingId = tokens.fontPairingId;
  if (!hasUsableFonts(tokens) && pairingId && PAIRING_BY_ID[pairingId]) {
    return applyFontsToThemeTokens(tokens, {
      ...fontsFromPairingId(pairingId),
      fontSource: tokens.fontSource || 'catalog',
    });
  }

  if (shouldSkipAiFontPick(tokens, context) && hasUsableFonts(tokens)) {
    return tokens;
  }

  const primaryHex = tokens.palette?.primary || tokens.palette?.accent || null;
  const contextText = [
    context.prompt,
    context.wizardBrief,
    context.tone,
    context.style,
    context.purpose,
    tokens.colorTreatment,
  ]
    .filter(Boolean)
    .join(' ');

  try {
    const aiFonts = await suggestFontsWithAi({
      prompt: context.prompt,
      wizardBrief: context.wizardBrief,
      tone: context.tone,
      audience: context.audience,
      purpose: context.purpose,
      style: context.style,
      primaryHex,
      colorTreatment: tokens.colorTreatment,
    });

    if (aiFonts?.fonts?.heading && aiFonts?.fonts?.body) {
      return applyFontsToThemeTokens(tokens, {
        ...aiFonts,
        fontSource: 'ai',
      });
    }
  } catch (err) {
    logger.warn('AI font pairing failed; using vibe fallback', { error: err.message });
  }

  const fallbackId = vibeFallbackPairingId(contextText);
  const fallback = fontsFromPairingId(fallbackId);
  return applyFontsToThemeTokens(tokens, {
    ...fallback,
    fontSource: 'ai',
  });
}

module.exports = {
  FONT_PAIRING_CATALOG,
  fontsFromPairingId,
  hasUsableFonts,
  mergeThemeTokensPreservingFonts,
  ensureThemeFonts,
  shouldSkipAiFontPick,
};
