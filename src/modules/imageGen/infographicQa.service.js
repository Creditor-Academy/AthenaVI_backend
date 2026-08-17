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
    sequenceBroken: false,
    missingSteps: false,
    illogicalData: false,
    yearErrors: false,
    overlap: false,
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
  const sequenceBroken = Boolean(parsed.sequenceBroken);
  const missingSteps = Boolean(parsed.missingSteps);
  const illogicalData = Boolean(parsed.illogicalData);
  const yearErrors = Boolean(parsed.yearErrors);
  const overlap = Boolean(parsed.overlap);
  const failFlags = garbledText || sequenceBroken || missingSteps || illogicalData || yearErrors || overlap;
  let pass = parsed.pass !== false && !failFlags;
  if (failFlags) pass = false;
  return {
    pass,
    issues,
    garbledText,
    sequenceBroken,
    missingSteps,
    illogicalData,
    yearErrors,
    overlap,
    suggestedTweak: parsed.suggestedTweak != null ? String(parsed.suggestedTweak).trim() : '',
    skipped: false,
  };
}

/**
 * Vision QA of a generated infographic against the planner spec.
 * Throws only on transport/parse after retries are not used — caller should fail-open.
 */
async function reviewInfographic({ buffer, spec = {} } = {}) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new AppError('Image buffer is required for infographic QA', 400);
  }

  const openai = getOpenAI();
  const dataUrl = `data:image/png;base64,${buffer.toString('base64')}`;
  const exactText = Array.isArray(spec.exactText) ? spec.exactText : [];
  const expected = Number(spec.expectedStepCount) || 0;
  const metrics = Array.isArray(spec.metrics) ? spec.metrics : [];
  const layout = spec.layout || 'custom';

  const system = [
    'You QA an infographic PNG against a typesetting spec.',
    'Return JSON only:',
    '{ "pass": true|false, "issues": ["..."], "garbledText": bool, "sequenceBroken": bool,',
    '"missingSteps": bool, "illogicalData": bool, "yearErrors": bool, "overlap": bool,',
    '"suggestedTweak": "one short image-edit instruction" }.',
    'Fail (pass=false) when: letters are merged/misspelled/gibberish; numbering skips, duplicates, or uses symbols;',
    'requested steps are missing vs expectedStepCount; funnel metrics increase; years are truncated (150 vs 1950);',
    'icons overlap text.',
    'Do not fail for minor style taste. suggestedTweak must name the exact strings to restore.',
  ].join(' ');

  const userText = [
    `Layout: ${layout}`,
    `Expected flow steps: ${expected}`,
    metrics.length ? `Metrics in order: ${metrics.join(' → ')}` : null,
    'Exact text that must appear (spelled exactly):',
    exactText.length ? exactText.map((t) => `- ${t}`).join('\n') : '(none listed)',
    'Inspect the image. Report QA JSON.',
  ]
    .filter(Boolean)
    .join('\n');

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
    throw new AppError('OpenAI vision returned empty infographic QA', 502);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AppError('OpenAI vision returned invalid infographic QA JSON', 502);
  }
  return normalizeQa(parsed);
}

async function reviewInfographicSafe(opts) {
  try {
    return await reviewInfographic(opts);
  } catch (err) {
    logger.warn('Infographic QA skipped', { message: err?.message });
    return emptyResult({ skipped: true });
  }
}

function buildFixInstruction(qa, spec = {}) {
  const issues = (qa?.issues || []).join('; ') || 'text or numbering looks wrong';
  const exact = Array.isArray(spec.exactText) ? spec.exactText : [];
  const lines = [
    'Correct spelling, numbering, and missing labels IN PLACE. Do not redesign layout, palette, or icons.',
    `Issues to fix: ${issues}`,
    'Restore sequential badges 01, 02, 03… with no gaps, duplicates, or symbols.',
    'Keep every requested step on canvas. Years must be four digits.',
  ];
  if (qa?.suggestedTweak) {
    lines.push(`Priority fix: ${qa.suggestedTweak}`);
  }
  if (exact.length) {
    lines.push('These strings must appear exactly:', ...exact.map((t) => `- "${t}"`));
  }
  return lines.join('\n');
}

module.exports = {
  reviewInfographic,
  reviewInfographicSafe,
  buildFixInstruction,
  emptyResult,
};
