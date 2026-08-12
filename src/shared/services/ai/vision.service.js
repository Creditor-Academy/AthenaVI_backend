const AppError = require('../../utils/AppError');
const { getOpenAI } = require('./openai.client');
const { DEFAULT_SLIDE_MODEL } = require('./llm.service');

/**
 * Check whether a candidate image matches the slide's concrete subject.
 * @param {{
 *   imageUrl?: string,
 *   imageBase64?: string,
 *   slideTitle?: string,
 *   slideText?: string,
 *   briefSubject?: string,
 *   model?: string,
 * }} opts
 * @returns {Promise<{ relevant: boolean, score: number, reason: string, latencyMs: number }>}
 */
async function checkImageRelevance({
  imageUrl,
  imageBase64,
  slideTitle = '',
  slideText = '',
  briefSubject = '',
  model,
} = {}) {
  const openai = getOpenAI();
  const resolvedModel = model || process.env.PPT_VISION_MODEL || DEFAULT_SLIDE_MODEL;

  let imagePart;
  if (imageUrl && String(imageUrl).trim()) {
    imagePart = { type: 'image_url', image_url: { url: String(imageUrl).trim() } };
  } else if (imageBase64 && String(imageBase64).trim()) {
    const raw = String(imageBase64).trim();
    const dataUrl = raw.startsWith('data:') ? raw : `data:image/png;base64,${raw}`;
    imagePart = { type: 'image_url', image_url: { url: dataUrl } };
  } else {
    throw new AppError('imageUrl or imageBase64 is required for vision relevance check', 400);
  }

  const system = [
    'You check whether an image clearly matches a presentation slide subject.',
    'Compare the image to the slide title, slide text, and image-brief subject.',
    'Return JSON only: { "relevant": true|false, "score": 0-1, "reason": "..." }.',
    'Fail (relevant=false) when the image is only topically adjacent or decorative without matching concrete nouns.',
    'score < 0.6 should set relevant=false.',
  ].join(' ');

  const userText = [
    `Slide title: ${slideTitle || '(none)'}`,
    `Slide bullets/body: ${slideText || '(none)'}`,
    `Image brief subject: ${briefSubject || '(none)'}`,
    'Does this image clearly match the slide\'s concrete subject?',
  ].join('\n');

  const started = Date.now();
  let completion;
  try {
    completion = await openai.chat.completions.create({
      model: resolvedModel,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: system },
        {
          role: 'user',
          content: [{ type: 'text', text: userText }, imagePart],
        },
      ],
    });
  } catch (err) {
    const msg = err?.message || 'OpenAI vision relevance check failed';
    const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
    throw new AppError(msg, status);
  }

  const latencyMs = Date.now() - started;
  const raw = completion?.choices?.[0]?.message?.content;
  if (!raw) {
    throw new AppError('OpenAI vision returned empty content', 502);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AppError('OpenAI vision returned invalid JSON', 502);
  }

  let score = Number(parsed.score);
  if (!Number.isFinite(score)) score = 0;
  score = Math.max(0, Math.min(1, score));

  let relevant = Boolean(parsed.relevant);
  if (score < 0.6) relevant = false;

  return {
    relevant,
    score,
    reason: parsed.reason != null ? String(parsed.reason) : '',
    latencyMs,
  };
}

/**
 * Summarize a reference image for image-gen context enrichment.
 * @param {{
 *   buffer?: Buffer,
 *   imageBase64?: string,
 *   mimeType?: string,
 *   hint?: string,
 *   model?: string,
 * }} opts
 * @returns {Promise<{ summary: string, latencyMs: number }>}
 */
async function summarizeReferenceImage({
  buffer,
  imageBase64,
  mimeType = 'image/png',
  hint = '',
  model,
} = {}) {
  const openai = getOpenAI();
  const resolvedModel =
    model ||
    process.env.IMAGE_GEN_VISION_MODEL ||
    process.env.PPT_VISION_MODEL ||
    DEFAULT_SLIDE_MODEL;

  let dataUrl;
  if (buffer && Buffer.isBuffer(buffer)) {
    const mime = String(mimeType || 'image/png').toLowerCase();
    dataUrl = `data:${mime};base64,${buffer.toString('base64')}`;
  } else if (imageBase64 && String(imageBase64).trim()) {
    const raw = String(imageBase64).trim();
    dataUrl = raw.startsWith('data:') ? raw : `data:image/png;base64,${raw}`;
  } else {
    throw new AppError('Image buffer or imageBase64 is required for reference summary', 400);
  }

  const imagePart = { type: 'image_url', image_url: { url: dataUrl } };
  const system = [
    'You summarize reference images for AI image generation.',
    'Describe subject, style, color palette, composition, lighting, typography/visible text, and mood.',
    'Return JSON only: { "summary": "..." }.',
    'Keep summary under 120 words. Be concrete and visual, not marketing fluff.',
  ].join(' ');

  const userText = [
    hint ? `User hint: ${String(hint).trim()}` : null,
    'Summarize this image as a visual reference for generating a new image.',
  ]
    .filter(Boolean)
    .join('\n');

  const started = Date.now();
  let completion;
  try {
    completion = await openai.chat.completions.create({
      model: resolvedModel,
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: system },
        {
          role: 'user',
          content: [{ type: 'text', text: userText }, imagePart],
        },
      ],
    });
  } catch (err) {
    const msg = err?.message || 'OpenAI vision reference summary failed';
    const status = err?.status >= 400 && err?.status < 600 ? err.status : 502;
    throw new AppError(msg, status);
  }

  const latencyMs = Date.now() - started;
  const raw = completion?.choices?.[0]?.message?.content;
  if (!raw) {
    throw new AppError('OpenAI vision returned empty content', 502);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AppError('OpenAI vision returned invalid JSON', 502);
  }

  const summary = parsed.summary != null ? String(parsed.summary).trim() : '';
  if (!summary) {
    throw new AppError('OpenAI vision returned empty summary', 502);
  }

  return { summary, latencyMs };
}

module.exports = {
  checkImageRelevance,
  summarizeReferenceImage,
};
