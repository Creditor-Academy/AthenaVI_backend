const AppError = require('../../utils/AppError');
const { getGemini } = require('./gemini.client');

const DEFAULT_GEMINI_IMAGE_MODEL = 'gemini-3-pro-image';

/** Ordered smallest → largest so tiers can be clamped per model. */
const IMAGE_SIZE_TIERS = ['512', '1K', '2K', '4K'];

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeTier(value) {
  if (value == null) return null;
  const raw = String(value).trim().toUpperCase();
  return IMAGE_SIZE_TIERS.includes(raw) ? raw : null;
}

/**
 * Clamp the requested tier to what the model supports.
 * Nano Banana 2 Lite is 1K-only, so a global 2K/4K default must not reach it.
 */
function resolveImageSize(requested, maxImageSize) {
  const fallback = normalizeTier(process.env.IMAGE_GEN_GEMINI_IMAGE_SIZE) || '2K';
  const want = normalizeTier(requested) || fallback;
  const max = normalizeTier(maxImageSize) || '4K';
  const wantIdx = IMAGE_SIZE_TIERS.indexOf(want);
  const maxIdx = IMAGE_SIZE_TIERS.indexOf(max);
  return IMAGE_SIZE_TIERS[Math.min(wantIdx, maxIdx)];
}

function bufferToPart(buffer, index = 0) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new AppError(`Gemini image input ${index + 1} must be a Buffer`, 400);
  }
  return {
    inlineData: {
      mimeType: 'image/png',
      data: buffer.toString('base64'),
    },
  };
}

function statusFromError(err) {
  const raw =
    err?.status ??
    err?.code ??
    err?.response?.status ??
    err?.error?.code ??
    null;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 400 && n < 600 ? n : null;
}

function isAbortError(err) {
  const name = err?.name || '';
  const message = err?.message || '';
  return (
    name === 'AbortError' ||
    name === 'TimeoutError' ||
    /aborted|AbortError|TimeoutError/i.test(message)
  );
}

function toAppError(err, fallbackMessage) {
  if (err instanceof AppError) return err;
  if (isAbortError(err)) {
    return new AppError(
      'Gemini image generation timed out — try again or a faster model (Flash / Flash Lite)',
      504
    );
  }
  const status = statusFromError(err);
  const message = err?.message || err?.error?.message || fallbackMessage;
  return new AppError(message, status || 502);
}

/**
 * Pull the first inline image out of the response. Text parts may precede it,
 * so every part is inspected rather than just parts[0].
 */
function extractImage(response) {
  const candidate = response?.candidates?.[0];
  const blockReason =
    response?.promptFeedback?.blockReason || candidate?.finishReason === 'SAFETY';
  const parts = candidate?.content?.parts || [];

  const texts = [];
  let b64 = null;
  for (const part of parts) {
    if (!b64 && part?.inlineData?.data) {
      b64 = part.inlineData.data;
    } else if (part?.text) {
      texts.push(String(part.text).trim());
    }
  }

  if (!b64) {
    if (blockReason) {
      throw new AppError(
        `Gemini blocked this image request (${response?.promptFeedback?.blockReason || 'safety'})`,
        400
      );
    }
    throw new AppError('Gemini image response contained no image data', 502);
  }

  return {
    b64,
    buffer: Buffer.from(b64, 'base64'),
    revised_prompt: texts.length ? texts.join('\n') : null,
  };
}

async function callGemini({ model, parts, aspectRatio, imageSize, maxImageSize }) {
  const ai = getGemini();
  const resolvedModel = model || DEFAULT_GEMINI_IMAGE_MODEL;
  const resolvedSize = resolveImageSize(imageSize, maxImageSize);
  // Pro often exceeds 3 minutes at 2K; default 5 minutes (override via env).
  const timeoutMs = envNumber('IMAGE_GEN_GEMINI_TIMEOUT_MS', 300000);

  const imageConfig = { imageSize: resolvedSize };
  if (aspectRatio) {
    imageConfig.aspectRatio = aspectRatio;
  }

  const request = {
    model: resolvedModel,
    contents: [{ role: 'user', parts }],
    config: {
      responseModalities: ['TEXT', 'IMAGE'],
      imageConfig,
      abortSignal: AbortSignal.timeout(timeoutMs),
    },
  };

  const started = Date.now();
  let response;
  let lastErr;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      response = await ai.models.generateContent(request);
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      const status = statusFromError(err);
      if (attempt === 0 && status && RETRYABLE_STATUS.has(status)) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 1500));
        continue;
      }
      break;
    }
  }

  if (lastErr) {
    throw toAppError(lastErr, 'Gemini image generation failed');
  }

  const extracted = extractImage(response);
  return {
    ...extracted,
    usage: response?.usageMetadata || null,
    latencyMs: Date.now() - started,
    model: resolvedModel,
    imageSize: resolvedSize,
  };
}

/**
 * Generate an image from a text prompt.
 * Returns the same shape as the OpenAI image service.
 */
async function generateImage({
  prompt,
  model = DEFAULT_GEMINI_IMAGE_MODEL,
  aspectRatio,
  imageSize,
  maxImageSize,
} = {}) {
  if (!prompt || !String(prompt).trim()) {
    throw new AppError('Image prompt is required', 400);
  }

  return callGemini({
    model,
    parts: [{ text: String(prompt).trim() }],
    aspectRatio,
    imageSize,
    maxImageSize,
  });
}

/**
 * Edit an existing image with a natural-language instruction.
 */
async function editImage({
  imageBuffer,
  instruction,
  model = DEFAULT_GEMINI_IMAGE_MODEL,
  aspectRatio,
  imageSize,
  maxImageSize,
} = {}) {
  if (!imageBuffer || !Buffer.isBuffer(imageBuffer)) {
    throw new AppError('Image buffer is required for edit', 400);
  }
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('Tweak instruction is required', 400);
  }

  return callGemini({
    model,
    parts: [{ text: String(instruction).trim() }, bufferToPart(imageBuffer)],
    aspectRatio,
    imageSize,
    maxImageSize,
  });
}

/**
 * Generate from a prompt plus reference images used as visual cues.
 */
async function generateImageWithReferences({
  prompt,
  referenceBuffers = [],
  model = DEFAULT_GEMINI_IMAGE_MODEL,
  aspectRatio,
  imageSize,
  maxImageSize,
} = {}) {
  if (!prompt || !String(prompt).trim()) {
    throw new AppError('Image prompt is required', 400);
  }
  if (!Array.isArray(referenceBuffers) || referenceBuffers.length === 0) {
    throw new AppError('At least one reference image buffer is required', 400);
  }

  const parts = [{ text: String(prompt).trim() }];
  referenceBuffers.forEach((buf, index) => parts.push(bufferToPart(buf, index)));

  return callGemini({
    model,
    parts,
    aspectRatio,
    imageSize,
    maxImageSize,
  });
}

module.exports = {
  generateImage,
  editImage,
  generateImageWithReferences,
  resolveImageSize,
  IMAGE_SIZE_TIERS,
  DEFAULT_GEMINI_IMAGE_MODEL,
};
