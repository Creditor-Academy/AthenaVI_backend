/**
 * Image Gen credit pricing — isolated from HeyGen/Remotion/PPT rates.
 */

const IMAGE_GEN_FEATURE = Object.freeze({
  GPT_IMAGE: 'image_gen_gpt_image',
  GPT_IMAGE_HD: 'image_gen_gpt_image_hd',
  DALL_E_3: 'image_gen_dall_e_3',
  GEMINI_PRO_IMAGE: 'image_gen_gemini_pro_image',
  GEMINI_FLASH_IMAGE: 'image_gen_gemini_flash_image',
  GEMINI_FLASH_LITE_IMAGE: 'image_gen_gemini_flash_lite_image',
  TWEAK: 'image_gen_tweak',
  INFOGRAPHIC: 'image_gen_infographic',
});

const FLAT_AC = Object.freeze({
  [IMAGE_GEN_FEATURE.GPT_IMAGE]: 6,
  [IMAGE_GEN_FEATURE.GPT_IMAGE_HD]: 12,
  // Same OpenAI call as HD (dall-e-3 is a catalog alias → gpt-image-1 high)
  [IMAGE_GEN_FEATURE.DALL_E_3]: 12,
  // Gemini placeholders until the ~20% margin pass; tiers track Google list price gaps
  [IMAGE_GEN_FEATURE.GEMINI_PRO_IMAGE]: 12,
  [IMAGE_GEN_FEATURE.GEMINI_FLASH_IMAGE]: 8,
  [IMAGE_GEN_FEATURE.GEMINI_FLASH_LITE_IMAGE]: 4,
  // Placeholder until ~20% margin pass; prefer getInfographicAc(modelId) which uses model AC
  [IMAGE_GEN_FEATURE.INFOGRAPHIC]: 12,
});

const MODEL_FEATURE = Object.freeze({
  'gpt-image-1': IMAGE_GEN_FEATURE.GPT_IMAGE,
  'gpt-image-1-hd': IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
  'dall-e-3': IMAGE_GEN_FEATURE.DALL_E_3,
  'gemini-3-pro-image': IMAGE_GEN_FEATURE.GEMINI_PRO_IMAGE,
  'gemini-3.1-flash-image': IMAGE_GEN_FEATURE.GEMINI_FLASH_IMAGE,
  'gemini-3.1-flash-lite-image': IMAGE_GEN_FEATURE.GEMINI_FLASH_LITE_IMAGE,
});

const FLAT_ENV_KEYS = Object.freeze({
  [IMAGE_GEN_FEATURE.GPT_IMAGE]: 'IMAGE_GEN_GPT_IMAGE_AC',
  [IMAGE_GEN_FEATURE.GPT_IMAGE_HD]: 'IMAGE_GEN_GPT_IMAGE_HD_AC',
  [IMAGE_GEN_FEATURE.DALL_E_3]: 'IMAGE_GEN_DALL_E_3_AC',
  [IMAGE_GEN_FEATURE.GEMINI_PRO_IMAGE]: 'IMAGE_GEN_GEMINI_PRO_AC',
  [IMAGE_GEN_FEATURE.GEMINI_FLASH_IMAGE]: 'IMAGE_GEN_GEMINI_FLASH_AC',
  [IMAGE_GEN_FEATURE.GEMINI_FLASH_LITE_IMAGE]: 'IMAGE_GEN_GEMINI_FLASH_LITE_AC',
  [IMAGE_GEN_FEATURE.INFOGRAPHIC]: 'IMAGE_GEN_INFOGRAPHIC_AC',
});

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getFlatAc(feature) {
  if (!(feature in FLAT_AC)) {
    return 0;
  }
  const envKey = FLAT_ENV_KEYS[feature];
  return Math.max(0, Math.floor(envNumber(envKey, FLAT_AC[feature])));
}

function getModelAc(modelId) {
  const feature = MODEL_FEATURE[modelId] || IMAGE_GEN_FEATURE.GPT_IMAGE;
  return getFlatAc(feature);
}

/**
 * Infographic flat charge. Until the margin pricing pass:
 * - If IMAGE_GEN_INFOGRAPHIC_AC is set, use that override.
 * - Else use getModelAc(modelId) so dogfood spend tracks the chosen model.
 */
function getInfographicAc(modelId) {
  const envKey = FLAT_ENV_KEYS[IMAGE_GEN_FEATURE.INFOGRAPHIC];
  const raw = process.env[envKey];
  if (raw != null && String(raw).trim() !== '') {
    return getFlatAc(IMAGE_GEN_FEATURE.INFOGRAPHIC);
  }
  return getModelAc(modelId || 'gpt-image-1-hd');
}

module.exports = {
  IMAGE_GEN_FEATURE,
  MODEL_FEATURE,
  getFlatAc,
  getModelAc,
  getInfographicAc,
};
