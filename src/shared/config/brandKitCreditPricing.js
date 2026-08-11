/**
 * Brand Kit AI credit pricing — flat AC per feature.
 */

const BRAND_KIT_FEATURE = Object.freeze({
  SUGGEST_COLORS: 'brand_kit_suggest_colors',
  SUGGEST_FONTS: 'brand_kit_suggest_fonts',
  SUGGEST_VOICE: 'brand_kit_suggest_voice',
  SUGGEST_IMAGE_STYLE: 'brand_kit_suggest_image_style',
  LOGO_VARIANTS: 'brand_kit_logo_variants',
  GUIDELINE_GENERATE: 'brand_kit_guideline_generate',
});

const FLAT_AC = Object.freeze({
  [BRAND_KIT_FEATURE.SUGGEST_COLORS]: 2,
  [BRAND_KIT_FEATURE.SUGGEST_FONTS]: 1,
  [BRAND_KIT_FEATURE.SUGGEST_VOICE]: 1,
  [BRAND_KIT_FEATURE.SUGGEST_IMAGE_STYLE]: 1,
  [BRAND_KIT_FEATURE.LOGO_VARIANTS]: 2,
  [BRAND_KIT_FEATURE.GUIDELINE_GENERATE]: 3,
});

const FLAT_ENV_KEYS = Object.freeze({
  [BRAND_KIT_FEATURE.SUGGEST_COLORS]: 'BRAND_KIT_SUGGEST_COLORS_AC',
  [BRAND_KIT_FEATURE.SUGGEST_FONTS]: 'BRAND_KIT_SUGGEST_FONTS_AC',
  [BRAND_KIT_FEATURE.SUGGEST_VOICE]: 'BRAND_KIT_SUGGEST_VOICE_AC',
  [BRAND_KIT_FEATURE.SUGGEST_IMAGE_STYLE]: 'BRAND_KIT_SUGGEST_IMAGE_STYLE_AC',
  [BRAND_KIT_FEATURE.LOGO_VARIANTS]: 'BRAND_KIT_LOGO_VARIANTS_AC',
  [BRAND_KIT_FEATURE.GUIDELINE_GENERATE]: 'BRAND_KIT_GUIDELINE_GENERATE_AC',
});

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getFlatAc(feature) {
  if (!(feature in FLAT_AC)) return 0;
  const envKey = FLAT_ENV_KEYS[feature];
  return Math.max(0, Math.floor(envNumber(envKey, FLAT_AC[feature])));
}

module.exports = {
  BRAND_KIT_FEATURE,
  getFlatAc,
};
