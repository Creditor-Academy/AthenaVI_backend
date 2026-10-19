const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { moderateText } = require('../../shared/services/ai/moderation.service');
const { chatJson } = require('../../shared/services/ai');
const { validatePrintSpec } = require('../validations/printSpec.validations');
const { getSpecModel } = require('./infographic.service');
const {
  SCHEMA_HINT,
  buildSystem,
  buildUser,
  buildCorrectiveUser,
} = require('./prompts/printSpec.prompt');
const { buildPrintRenderPrompt, buildPrintCopyBlock } = require('./prompts/printRender.prompt');
const {
  buildRouterSystem,
  buildRouterUser,
  buildSpecPatchSystem,
  buildSpecPatchUser,
  classifyEditHeuristic,
} = require('./prompts/printChat.prompt');
const { parseAspect } = require('./prompts/socialRender.prompt');

const TEXT_FIELDS = Object.freeze(['headline', 'subheadline', 'cta']);

const FIELD_LABELS = Object.freeze({
  headline: 'Headline',
  subheadline: 'Subheadline',
  cta: 'Call to action',
});

function truncateAtWord(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const lastSpace = cut.lastIndexOf(' ');
  return (lastSpace >= Math.floor(max * 0.6) ? cut.slice(0, lastSpace) : cut).trim();
}

/**
 * Enforce per-size copy limits and stamp size fields.
 * A limit of 0 drops that field; extra detail lines are dropped.
 */
function clampCopy(spec, format) {
  const warnings = [];
  const limits = (format && format.textLimits) || {};
  const next = { ...spec };
  const sizeName = format ? format.name : 'this size';

  for (const field of TEXT_FIELDS) {
    const value = next[field] != null ? String(next[field]).trim() : '';
    const max = limits[field];
    if (!value || max == null) {
      next[field] = value;
      continue;
    }
    if (max === 0) {
      if (field !== 'headline') {
        next[field] = '';
        warnings.push(`${FIELD_LABELS[field]} removed; ${sizeName} has no ${FIELD_LABELS[field].toLowerCase()}.`);
      }
      continue;
    }
    if (value.length > max) {
      next[field] = truncateAtWord(value, max);
      warnings.push(
        `${FIELD_LABELS[field]} shortened from ${value.length} to ${next[field].length} characters for ${sizeName} (max ${max}).`
      );
    } else {
      next[field] = value;
    }
  }

  const rawDetails = Array.isArray(next.details)
    ? next.details.map((d) => String(d || '').trim()).filter(Boolean)
    : [];
  const maxLines = limits.details ?? rawDetails.length;
  const maxLine = limits.detailLine;
  let details = rawDetails;
  if (details.length > maxLines) {
    warnings.push(
      `${details.length - maxLines} detail line(s) dropped; ${sizeName} fits ${maxLines}.`
    );
    details = details.slice(0, maxLines);
  }
  if (maxLine) {
    details = details.map((line) => {
      if (line.length <= maxLine) return line;
      const cut = truncateAtWord(line, maxLine);
      warnings.push(`Detail line shortened from ${line.length} to ${cut.length} characters (max ${maxLine}).`);
      return cut;
    });
  }
  next.details = details;

  if (format) {
    next.formatId = format.id;
    next.kind = format.kind;
    next.safeZone = format.safeZone;
  }

  return { spec: next, warnings };
}

function joiErrorMessages(error) {
  if (!error || !error.details) return [error?.message || 'validation failed'];
  return error.details.map((d) => d.message);
}

function validate(spec) {
  const { value, error } = validatePrintSpec(spec);
  if (error) {
    return { ok: false, errors: joiErrorMessages(error), value: null };
  }
  return { ok: true, errors: [], value };
}

/** Run a spec LLM call with one corrective retry; throws 400 when both fail validation. */
async function requestSpec({ system, user, temperature }) {
  const model = getSpecModel();
  let result;
  try {
    result = await chatJson({ system, user, model, schemaHint: SCHEMA_HINT, temperature });
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(err?.message || 'Print design spec generation failed', 502);
  }

  let validated = validate(result.data);
  if (!validated.ok) {
    try {
      const retry = await chatJson({
        system,
        user: `${user}\n\n${buildCorrectiveUser(validated.errors)}`,
        model,
        schemaHint: SCHEMA_HINT,
        temperature: 0.2,
      });
      validated = validate(retry.data);
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(messages.IMAGE_GEN_PRINT_SPEC_INVALID, 400);
    }
  }

  if (!validated.ok) {
    throw new AppError(
      validated.errors.length ? validated.errors : messages.IMAGE_GEN_PRINT_SPEC_INVALID,
      400
    );
  }
  return { value: validated.value, usage: result.usage || null };
}

/**
 * Free-text prompt (+ optional context) → validated PrintSpec for one print size.
 */
async function buildSpec({
  prompt,
  contextText = '',
  styleHint = null,
  brandPalette = null,
  format,
} = {}) {
  if (!prompt || !String(prompt).trim()) {
    throw new AppError('prompt is required', 400);
  }
  if (!format) {
    throw new AppError('formatId is required for printable mode', 400);
  }

  await moderateText(String(prompt).trim());

  const { value, usage } = await requestSpec({
    system: buildSystem(),
    user: buildUser({
      userPrompt: String(prompt).trim(),
      contextText,
      styleHint,
      brandPalette,
      format,
    }),
    temperature: 0.4,
  });

  const clamped = clampCopy(value, format);
  return { spec: clamped.spec, warnings: clamped.warnings, usage };
}

/**
 * Patch an existing PrintSpec from a chat/tweak instruction; the size is kept.
 */
async function patchSpec({ spec, instruction, format } = {}) {
  if (!spec || typeof spec !== 'object') {
    throw new AppError(messages.IMAGE_GEN_PRINT_SPEC_INVALID, 400);
  }
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('instruction is required', 400);
  }

  await moderateText(String(instruction).trim());

  const { value } = await requestSpec({
    system: buildSpecPatchSystem(),
    user: buildSpecPatchUser({ spec, instruction: String(instruction).trim(), format }),
    temperature: 0.3,
  });

  const merged = {
    ...value,
    visualStyle:
      value.visualStyle != null && String(value.visualStyle).trim()
        ? value.visualStyle
        : spec.visualStyle || null,
    palette:
      Array.isArray(value.palette) && value.palette.length ? value.palette : spec.palette || undefined,
  };

  return clampCopy(merged, format);
}

/** Width/height ratio of the canvas the provider actually renders. */
function providerAspectFor({ size, aspectRatio } = {}) {
  return parseAspect(aspectRatio) || parseAspect(size);
}

function buildRenderPrompt({ spec, format, sizing = {}, hasReferences = false }) {
  return buildPrintRenderPrompt({
    spec,
    format,
    providerAspect: providerAspectFor(sizing),
    hasReferences,
  });
}

/** Pixel-edit prompt for a print design: apply the visual change, keep every printed word. */
function buildPixelEditInstruction({ instruction, spec } = {}) {
  const lines = [String(instruction || '').trim(), ''];
  lines.push(
    'Keep every existing printed word exactly as written, in the same place and legible. Do not add new text.',
    'Keep it flat print artwork: no mockup, frame, perspective, or crop marks.'
  );
  if (spec && spec.headline) {
    lines.push('', 'Existing printed text:', buildPrintCopyBlock(spec));
  }
  lines.push(
    '',
    'Any blurred outer border is padding that will be cropped away: keep text and logos in the sharp central area.'
  );
  return lines.join('\n');
}

async function classifyEditWithLlm(instruction) {
  try {
    const result = await chatJson({
      system: buildRouterSystem(),
      user: buildRouterUser(instruction),
      model: getSpecModel(),
      schemaHint: { editMode: 'spec|pixel', reason: 'string' },
      temperature: 0,
    });
    const mode = result?.data?.editMode;
    if (mode === 'pixel' || mode === 'spec') return mode;
  } catch {
    // fall through
  }
  return 'spec';
}

/**
 * @returns {Promise<'spec'|'pixel'>}
 */
async function classifyEdit({ instruction, editMode = null } = {}) {
  if (editMode === 'spec' || editMode === 'pixel') {
    return editMode;
  }
  const heuristic = classifyEditHeuristic(instruction);
  if (heuristic) return heuristic;
  return classifyEditWithLlm(instruction);
}

module.exports = {
  clampCopy,
  buildSpec,
  patchSpec,
  buildRenderPrompt,
  providerAspectFor,
  buildPixelEditInstruction,
  classifyEdit,
};
