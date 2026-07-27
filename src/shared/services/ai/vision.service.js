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

module.exports = {
  checkImageRelevance,
};
