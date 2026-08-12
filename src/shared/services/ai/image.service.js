const AppError = require('../../utils/AppError');
const { getOpenAI } = require('./openai.client');
const { toFile } = require('openai');

const DEFAULT_IMAGE_MODEL = process.env.PPT_IMAGE_MODEL || 'gpt-image-1';

/**
 * Map public quality knobs to OpenAI image quality values.
 * @param {'standard'|'hd'|'low'|'medium'|'high'|string} quality
 * @param {string} model
 */
function mapQuality(quality, model) {
  const isGptImage = String(model || '').startsWith('gpt-image');
  if (isGptImage) {
    if (quality === 'hd' || quality === 'high') return 'high';
    if (quality === 'standard' || quality === 'medium') return 'medium';
    if (quality === 'low') return 'low';
    return quality || 'medium';
  }
  // Legacy non–gpt-image models (no longer offered in image-gen catalog)
  if (quality === 'hd' || quality === 'high') return 'hd';
  return 'standard';
}

function extractB64(response) {
  const image = response?.data?.[0];
  const b64 = image?.b64_json;
  if (!b64) {
    throw new AppError('OpenAI image response missing b64_json', 502);
  }
  return {
    b64,
    buffer: Buffer.from(b64, 'base64'),
    revised_prompt: image?.revised_prompt || null,
  };
}

/**
 * Generate an image via OpenAI Images API (b64_json).
 * @param {{ prompt: string, quality?: string, model?: string, size?: string }} opts
 */
async function generateImage({
  prompt,
  quality = 'standard',
  model = DEFAULT_IMAGE_MODEL,
  size,
} = {}) {
  const openai = getOpenAI();
  const resolvedModel = model || DEFAULT_IMAGE_MODEL;

  if (!prompt || !String(prompt).trim()) {
    throw new AppError('Image prompt is required', 400);
  }

  const params = {
    model: resolvedModel,
    prompt: String(prompt),
    quality: mapQuality(quality, resolvedModel),
    n: 1,
  };
  if (size) {
    params.size = size;
  }

  const started = Date.now();
  let response;
  try {
    response = await openai.images.generate({
      ...params,
      response_format: 'b64_json',
    });
  } catch (err) {
    if (err?.message && /response_format/i.test(err.message)) {
      try {
        response = await openai.images.generate(params);
      } catch (retryErr) {
        const msg = retryErr?.message || 'OpenAI image generation failed';
        const status = retryErr?.status >= 400 && retryErr?.status < 600 ? retryErr.status : 502;
        throw new AppError(msg, status);
      }
    } else {
      const msg = err?.message || 'OpenAI image generation failed';
      const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
      throw new AppError(msg, status);
    }
  }

  const extracted = extractB64(response);
  return {
    ...extracted,
    usage: response?.usage || null,
    latencyMs: Date.now() - started,
    model: resolvedModel,
  };
}

/**
 * Edit an existing image via OpenAI Images Edit API.
 * Uses gpt-image models only.
 * @param {{ imageBuffer: Buffer, instruction: string, model?: string, size?: string, quality?: string }} opts
 */
async function editImage({
  imageBuffer,
  instruction,
  model = 'gpt-image-1',
  size,
  quality = 'standard',
} = {}) {
  const openai = getOpenAI();
  let resolvedModel = model || 'gpt-image-1';
  if (!String(resolvedModel).startsWith('gpt-image')) {
    resolvedModel = 'gpt-image-1';
  }

  if (!imageBuffer || !Buffer.isBuffer(imageBuffer)) {
    throw new AppError('Image buffer is required for edit', 400);
  }
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('Tweak instruction is required', 400);
  }

  const file = await toFile(imageBuffer, 'source.png', { type: 'image/png' });
  const params = {
    model: resolvedModel,
    image: file,
    prompt: String(instruction).trim(),
    quality: mapQuality(quality, resolvedModel),
    n: 1,
  };
  if (size) {
    params.size = size;
  }

  const started = Date.now();
  let response;
  try {
    response = await openai.images.edit({
      ...params,
      response_format: 'b64_json',
    });
  } catch (err) {
    if (err?.message && /response_format/i.test(err.message)) {
      try {
        response = await openai.images.edit(params);
      } catch (retryErr) {
        const msg = retryErr?.message || 'OpenAI image edit failed';
        const status = retryErr?.status >= 400 && retryErr?.status < 600 ? retryErr.status : 502;
        throw new AppError(msg, status);
      }
    } else {
      const msg = err?.message || 'OpenAI image edit failed';
      const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
      throw new AppError(msg, status);
    }
  }

  const extracted = extractB64(response);
  return {
    ...extracted,
    usage: response?.usage || null,
    latencyMs: Date.now() - started,
    model: resolvedModel,
  };
}

/**
 * Generate an image from a prompt plus optional reference images via Images Edit API.
 * Uses gpt-image models only. Passes multiple images as visual references.
 * @param {{
 *   prompt: string,
 *   referenceBuffers: Buffer[],
 *   model?: string,
 *   size?: string,
 *   quality?: string,
 *   inputFidelity?: string,
 * }} opts
 */
async function generateImageWithReferences({
  prompt,
  referenceBuffers = [],
  model = 'gpt-image-1',
  size,
  quality = 'standard',
  inputFidelity,
} = {}) {
  const openai = getOpenAI();
  let resolvedModel = model || 'gpt-image-1';
  if (!String(resolvedModel).startsWith('gpt-image')) {
    resolvedModel = 'gpt-image-1';
  }

  if (!prompt || !String(prompt).trim()) {
    throw new AppError('Image prompt is required', 400);
  }
  if (!Array.isArray(referenceBuffers) || referenceBuffers.length === 0) {
    throw new AppError('At least one reference image buffer is required', 400);
  }
  if (referenceBuffers.length > 5) {
    throw new AppError('At most 5 reference images are allowed', 400);
  }

  const files = [];
  for (let i = 0; i < referenceBuffers.length; i += 1) {
    const buf = referenceBuffers[i];
    if (!buf || !Buffer.isBuffer(buf)) {
      throw new AppError('Each reference image must be a Buffer', 400);
    }
    // eslint-disable-next-line no-await-in-loop
    const file = await toFile(buf, `reference-${i + 1}.png`, { type: 'image/png' });
    files.push(file);
  }

  const fidelity =
    inputFidelity ||
    (process.env.IMAGE_GEN_REFERENCE_INPUT_FIDELITY &&
      String(process.env.IMAGE_GEN_REFERENCE_INPUT_FIDELITY).trim()) ||
    'high';

  const params = {
    model: resolvedModel,
    image: files,
    prompt: String(prompt).trim(),
    quality: mapQuality(quality, resolvedModel),
    n: 1,
  };
  if (size) {
    params.size = size;
  }
  if (fidelity === 'low' || fidelity === 'high') {
    params.input_fidelity = fidelity;
  }

  const started = Date.now();
  let response;
  try {
    response = await openai.images.edit({
      ...params,
      response_format: 'b64_json',
    });
  } catch (err) {
    if (err?.message && /response_format/i.test(err.message)) {
      try {
        response = await openai.images.edit(params);
      } catch (retryErr) {
        const msg = retryErr?.message || 'OpenAI image generation with references failed';
        const status = retryErr?.status >= 400 && retryErr?.status < 600 ? retryErr.status : 502;
        throw new AppError(msg, status);
      }
    } else {
      const msg = err?.message || 'OpenAI image generation with references failed';
      const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
      throw new AppError(msg, status);
    }
  }

  const extracted = extractB64(response);
  return {
    ...extracted,
    usage: response?.usage || null,
    latencyMs: Date.now() - started,
    model: resolvedModel,
  };
}

module.exports = {
  generateImage,
  editImage,
  generateImageWithReferences,
  mapQuality,
  DEFAULT_IMAGE_MODEL,
};
