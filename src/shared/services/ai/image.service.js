const AppError = require('../../utils/AppError');
const { getOpenAI } = require('./openai.client');

const DEFAULT_IMAGE_MODEL = process.env.PPT_IMAGE_MODEL || 'gpt-image-1';

/**
 * Map public quality knobs to OpenAI image quality values.
 * @param {'standard'|'hd'|string} quality
 */
function mapQuality(quality) {
  if (quality === 'hd') return 'high';
  if (quality === 'standard') return 'medium';
  return quality || 'medium';
}

/**
 * Generate an image via OpenAI Images API (b64_json).
 * @param {{ prompt: string, quality?: 'standard'|'hd' }} opts
 * @returns {Promise<{ b64: string, buffer: Buffer, revised_prompt: string|null, usage: object|null, latencyMs: number }>}
 */
async function generateImage({ prompt, quality = 'standard' } = {}) {
  const openai = getOpenAI();
  const model = DEFAULT_IMAGE_MODEL;

  if (!prompt || !String(prompt).trim()) {
    throw new AppError('Image prompt is required', 400);
  }

  const started = Date.now();
  let response;
  try {
    response = await openai.images.generate({
      model,
      prompt: String(prompt),
      quality: mapQuality(quality),
      // GPT image models return b64 by default; set explicitly for dall-e fallbacks.
      response_format: 'b64_json',
      n: 1,
    });
  } catch (err) {
    // Some GPT image models reject response_format — retry without it.
    if (err?.message && /response_format/i.test(err.message)) {
      try {
        response = await openai.images.generate({
          model,
          prompt: String(prompt),
          quality: mapQuality(quality),
          n: 1,
        });
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

  const latencyMs = Date.now() - started;
  const image = response?.data?.[0];
  const b64 = image?.b64_json;

  if (!b64) {
    throw new AppError('OpenAI image response missing b64_json', 502);
  }

  return {
    b64,
    buffer: Buffer.from(b64, 'base64'),
    revised_prompt: image?.revised_prompt || null,
    usage: response?.usage || null,
    latencyMs,
  };
}

module.exports = {
  generateImage,
  DEFAULT_IMAGE_MODEL,
};
