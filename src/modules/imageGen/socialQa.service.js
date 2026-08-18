const AppError = require('../../shared/utils/AppError');
const { getOpenAI } = require('../../shared/services/ai');
const { DEFAULT_SLIDE_MODEL } = require('../../shared/services/ai/llm.service');
const logger = require('../../shared/utils/logger');

function visionModel() {
  return (
    process.env.IMAGE_GEN_VISION_MODEL ||
    process.env.PPT_VISION_MODEL ||
    DEFAULT_SLIDE_MODEL
  );
}

function emptyResult(overrides = {}) {
  return {
    pass: true,
    issues: [],
    garbledText: false,
    cutoff: false,
    sequenceBroken: false,
    suggestedTweak: '',
    skipped: false,
    ...overrides,
  };
}

function normalizeQa(parsed) {
  const issues = Array.isArray(parsed.issues)
    ? parsed.issues.map((i) => String(i)).filter(Boolean)
    : [];
  const garbledText = Boolean(parsed.garbledText);
  const cutoff = Boolean(parsed.cutoff);
  const sequenceBroken = Boolean(parsed.sequenceBroken);
  const failFlags = garbledText || cutoff || sequenceBroken;
  let pass = parsed.pass !== false && !failFlags;
  if (failFlags) pass = false;
  return {
    pass,
    issues,
    garbledText,
    cutoff,
    sequenceBroken,
    suggestedTweak: parsed.suggestedTweak != null ? String(parsed.suggestedTweak).trim() : '',
    skipped: false,
  };
}

/**
 * Vision QA for baked social: exact headline spelling, edge cutoff, sequence skip/dup.
 */
async function reviewSocial({ buffer, headline, subheadline } = {}) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new AppError('Image buffer is required for social QA', 400);
  }

  const openai = getOpenAI();
  const dataUrl = `data:image/png;base64,${buffer.toString('base64')}`;
  const head = headline != null ? String(headline).trim() : '';
  const sub = subheadline != null ? String(subheadline).trim() : '';

  const system = [
    'You QA a social-media PNG that was asked to typeset a headline.',
    'Return JSON only:',
    '{ "pass": true|false, "issues": ["..."], "garbledText": bool, "cutoff": bool,',
    '"sequenceBroken": bool, "suggestedTweak": "one short image-edit instruction" }.',
    'Fail when: headline/subheadline letters are merged, misspelled, or gibberish vs the exact strings;',
    'type is clipped by canvas edges or UI chrome; numbered steps skip, duplicate, or use symbols (01, 02…).',
    'Do not fail for style taste. suggestedTweak must name the exact strings to restore.',
  ].join(' ');

  const userText = [
    head ? `Exact headline (must appear spelled exactly): "${head}"` : 'No headline was requested.',
    sub ? `Exact subheadline (must appear spelled exactly): "${sub}"` : 'No subheadline was requested.',
    'Inspect the image. Report QA JSON.',
  ].join('\n');

  const completion = await openai.chat.completions.create({
    model: visionModel(),
    temperature: 0,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      {
        role: 'user',
        content: [
          { type: 'text', text: userText },
          { type: 'image_url', image_url: { url: dataUrl } },
        ],
      },
    ],
  });

  const raw = completion?.choices?.[0]?.message?.content;
  if (!raw) {
    throw new AppError('OpenAI vision returned empty social QA', 502);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AppError('OpenAI vision returned invalid social QA JSON', 502);
  }
  return normalizeQa(parsed);
}

async function reviewSocialSafe(opts) {
  try {
    return await reviewSocial(opts);
  } catch (err) {
    logger.warn('Social QA skipped', { message: err?.message });
    return emptyResult({ skipped: true });
  }
}

function buildSocialFixInstruction(qa, { headline, subheadline } = {}) {
  const issues = (qa?.issues || []).join('; ') || 'headline text looks wrong or cut off';
  const lines = [
    'Correct spelling and clipped type IN PLACE. Do not redesign layout, palette, or photography.',
    `Issues to fix: ${issues}`,
    'Keep all headline letters fully on-canvas with clear margins. No warped or merged glyphs.',
  ];
  if (qa?.suggestedTweak) {
    lines.push(`Priority fix: ${qa.suggestedTweak}`);
  }
  const headlineTrim = headline != null ? String(headline).trim() : '';
  const subTrim = subheadline != null ? String(subheadline).trim() : '';
  if (headlineTrim) {
    lines.push(`Headline must read exactly: "${headlineTrim}"`);
  }
  if (subTrim) {
    lines.push(`Subheadline must read exactly: "${subTrim}"`);
  }
  return lines.join('\n');
}

module.exports = {
  reviewSocial,
  reviewSocialSafe,
  buildSocialFixInstruction,
  emptyResult,
};
