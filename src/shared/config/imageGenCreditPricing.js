/**
 * Image Gen credit pricing — isolated from HeyGen/Remotion/PPT rates.
 */

const IMAGE_GEN_FEATURE = Object.freeze({
  GPT_IMAGE: 'image_gen_gpt_image',
  GPT_IMAGE_HD: 'image_gen_gpt_image_hd',
  DALL_E_3: 'image_gen_dall_e_3',
  INFOGRAPHIC_SURCHARGE: 'image_gen_infographic_surcharge',
  SOCIAL_SURCHARGE: 'image_gen_social_surcharge',
  TWEAK: 'image_gen_tweak',
});

const FLAT_AC = Object.freeze({
  [IMAGE_GEN_FEATURE.GPT_IMAGE]: 6,
  [IMAGE_GEN_FEATURE.GPT_IMAGE_HD]: 12,
  // Same OpenAI call as HD (dall-e-3 is a catalog alias → gpt-image-1 high)
  [IMAGE_GEN_FEATURE.DALL_E_3]: 12,
  [IMAGE_GEN_FEATURE.INFOGRAPHIC_SURCHARGE]: 2,
  [IMAGE_GEN_FEATURE.SOCIAL_SURCHARGE]: 1,
});

const MODEL_FEATURE = Object.freeze({
  'gpt-image-1': IMAGE_GEN_FEATURE.GPT_IMAGE,
  'gpt-image-1-hd': IMAGE_GEN_FEATURE.GPT_IMAGE_HD,
  'dall-e-3': IMAGE_GEN_FEATURE.DALL_E_3,
});

const FLAT_ENV_KEYS = Object.freeze({
  [IMAGE_GEN_FEATURE.GPT_IMAGE]: 'IMAGE_GEN_GPT_IMAGE_AC',
  [IMAGE_GEN_FEATURE.GPT_IMAGE_HD]: 'IMAGE_GEN_GPT_IMAGE_HD_AC',
  [IMAGE_GEN_FEATURE.DALL_E_3]: 'IMAGE_GEN_DALL_E_3_AC',
  [IMAGE_GEN_FEATURE.INFOGRAPHIC_SURCHARGE]: 'IMAGE_GEN_INFOGRAPHIC_SURCHARGE_AC',
  [IMAGE_GEN_FEATURE.SOCIAL_SURCHARGE]: 'IMAGE_GEN_SOCIAL_SURCHARGE_AC',
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

function getModeSurcharge(mode) {
  if (mode === 'infographic') {
    return getFlatAc(IMAGE_GEN_FEATURE.INFOGRAPHIC_SURCHARGE);
  }
  if (mode === 'social') {
    return getFlatAc(IMAGE_GEN_FEATURE.SOCIAL_SURCHARGE);
  }
  return 0;
}

module.exports = {
  IMAGE_GEN_FEATURE,
  MODEL_FEATURE,
  getFlatAc,
  getModelAc,
  getModeSurcharge,
};
