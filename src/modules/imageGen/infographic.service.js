const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { moderateText } = require('../../shared/services/ai/moderation.service');
const { chatJson, DEFAULT_SLIDE_MODEL } = require('../../shared/services/ai');
const { validateInfographicSpec } = require('../validations/infographicSpec.validations');
const { maxSectionsFor, resolveArchetype } = require('./catalogs/archetypes');
const { styleSuffix, resolveStyle } = require('./catalogs/styles');
const {
  SCHEMA_HINT,
  buildSystem,
  buildUser,
  buildCorrectiveUser,
} = require('./prompts/infographicSpec.prompt');
const { buildInfographicRenderPrompt } = require('./prompts/infographicRender.prompt');
const {
  buildRouterSystem,
  buildRouterUser,
  buildSpecPatchSystem,
  buildSpecPatchUser,
  classifyEditHeuristic,
} = require('./prompts/infographicChat.prompt');

function getSpecModel() {
  const env = process.env.IMAGE_GEN_SPEC_MODEL;
  if (env && String(env).trim()) return String(env).trim();
  return DEFAULT_SLIDE_MODEL;
}

/**
 * Merge styleHint with optional style/styleId catalog suffix.
 */
function mergeStyleHint({ styleHint, style, styleId } = {}) {
  const parts = [];
  const hint = styleHint != null ? String(styleHint).trim() : '';
  if (hint) parts.push(hint);
  const catalogId = styleId || style;
  if (catalogId && resolveStyle(catalogId)) {
    const suffix = styleSuffix(catalogId);
    if (suffix) parts.push(suffix);
  }
  return parts.filter(Boolean).join(' ').trim() || null;
}

function countSpecItems(spec) {
  if (!spec || typeof spec !== 'object') return 0;
  if (Array.isArray(spec.flows) && spec.flows.length) {
    return spec.flows.reduce(
      (sum, flow) => sum + (Array.isArray(flow.sections) ? flow.sections.length : 0),
      0
    );
  }
  return Array.isArray(spec.sections) ? spec.sections.length : 0;
}

/**
 * Truncate sections/flows to orientation max; return warnings.
 */
function clampSections(spec, format) {
  const warnings = [];
  if (!spec || typeof spec !== 'object') {
    return { spec, warnings };
  }
  const orientation = (format && format.id) || spec.orientation || 'landscape';
  const archetypeId = spec.archetype || 'process';
  const max = maxSectionsFor(archetypeId, orientation);
  const next = { ...spec, orientation };

  if (Array.isArray(next.flows) && next.flows.length) {
    let remaining = max;
    const clampedFlows = [];
    for (const flow of next.flows) {
      if (remaining <= 0) break;
      const sections = Array.isArray(flow.sections) ? flow.sections : [];
      const take = sections.slice(0, remaining);
      remaining -= take.length;
      if (take.length) {
        clampedFlows.push({ ...flow, sections: take });
      }
    }
    const before = countSpecItems(spec);
    const after = countSpecItems({ flows: clampedFlows });
    if (after < before) {
      warnings.push(
        `Truncated content from ${before} to ${after} items for ${orientation} ${archetypeId} (max ${max}).`
      );
    }
    next.flows = clampedFlows;
    delete next.sections;
  } else if (Array.isArray(next.sections)) {
    const before = next.sections.length;
    if (before > max) {
      next.sections = next.sections.slice(0, max);
      warnings.push(
        `Truncated sections from ${before} to ${max} for ${orientation} ${archetypeId}.`
      );
    }
    delete next.flows;
  }

  return { spec: next, warnings };
}

function joiErrorMessages(error) {
  if (!error || !error.details) return [error?.message || 'validation failed'];
  return error.details.map((d) => d.message);
}

async function validateOrThrow(spec) {
  const { value, error } = validateInfographicSpec(spec);
  if (error) {
    return { ok: false, errors: joiErrorMessages(error), value: null };
  }
  return { ok: true, errors: [], value };
}

/**
 * LLM → InfographicSpec with one corrective retry.
 */
async function buildSpec({
  prompt,
  contextText = '',
  archetypeHint = null,
  styleHint = null,
  format = null,
} = {}) {
  if (!prompt || !String(prompt).trim()) {
    throw new AppError('prompt is required', 400);
  }

  await moderateText(String(prompt).trim());

  const orientation = (format && format.id) || 'landscape';
  const hintArchetype =
    archetypeHint && resolveArchetype(archetypeHint) ? archetypeHint : null;
  const maxSections = maxSectionsFor(hintArchetype || 'process', orientation);
  const model = getSpecModel();

  const system = buildSystem();
  const user = buildUser({
    userPrompt: String(prompt).trim(),
    contextText,
    archetypeHint: hintArchetype,
    styleHint,
    orientation,
    maxSections,
  });

  let result;
  try {
    result = await chatJson({
      system,
      user,
      model,
      schemaHint: SCHEMA_HINT,
      temperature: 0.3,
    });
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(err?.message || 'Infographic spec generation failed', 502);
  }

  let validated = await validateOrThrow(result.data);
  if (!validated.ok) {
    try {
      const retry = await chatJson({
        system,
        user: `${user}\n\n${buildCorrectiveUser(validated.errors)}`,
        model,
        schemaHint: SCHEMA_HINT,
        temperature: 0.2,
      });
      validated = await validateOrThrow(retry.data);
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(messages.IMAGE_GEN_SPEC_INVALID, 400);
    }
  }

  if (!validated.ok) {
    throw new AppError(validated.errors.length ? validated.errors : messages.IMAGE_GEN_SPEC_INVALID, 400);
  }

  let spec = { ...validated.value, orientation };
  if (hintArchetype) {
    spec.archetype = hintArchetype;
  }

  const clamped = clampSections(spec, format);
  return {
    spec: clamped.spec,
    warnings: clamped.warnings,
    usage: result.usage || null,
  };
}

function buildRenderPrompt({ spec, format, hasReferences = false }) {
  return buildInfographicRenderPrompt({ spec, format, hasReferences });
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

/**
 * Patch an existing InfographicSpec from a chat/tweak instruction.
 */
async function patchSpec({ spec, instruction, format = null } = {}) {
  if (!spec || typeof spec !== 'object') {
    throw new AppError(messages.IMAGE_GEN_SPEC_INVALID, 400);
  }
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('instruction is required', 400);
  }

  await moderateText(String(instruction).trim());

  const model = getSpecModel();
  let result;
  try {
    result = await chatJson({
      system: buildSpecPatchSystem(),
      user: buildSpecPatchUser({ spec, instruction: String(instruction).trim() }),
      model,
      schemaHint: SCHEMA_HINT,
      temperature: 0.3,
    });
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(err?.message || 'Infographic spec patch failed', 502);
  }

  let validated = await validateOrThrow(result.data);
  if (!validated.ok) {
    try {
      const retry = await chatJson({
        system: buildSpecPatchSystem(),
        user: `${buildSpecPatchUser({
          spec,
          instruction: String(instruction).trim(),
        })}\n\n${buildCorrectiveUser(validated.errors)}`,
        model,
        schemaHint: SCHEMA_HINT,
        temperature: 0.2,
      });
      validated = await validateOrThrow(retry.data);
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(messages.IMAGE_GEN_SPEC_INVALID, 400);
    }
  }

  if (!validated.ok) {
    throw new AppError(validated.errors.length ? validated.errors : messages.IMAGE_GEN_SPEC_INVALID, 400);
  }

  const orientation =
    (format && format.id) ||
    spec.orientation ||
    validated.value.orientation ||
    'landscape';
  let next = {
    ...validated.value,
    orientation,
    // Preserve look unless the patched spec explicitly changed visualStyle/palette
    // (the prompt already asks to preserve; this is a safety net for empties)
    visualStyle:
      validated.value.visualStyle != null && String(validated.value.visualStyle).trim()
        ? validated.value.visualStyle
        : spec.visualStyle || null,
    palette:
      Array.isArray(validated.value.palette) && validated.value.palette.length
        ? validated.value.palette
        : spec.palette || undefined,
  };

  const clamped = clampSections(next, format || { id: orientation });
  return {
    spec: clamped.spec,
    warnings: clamped.warnings,
  };
}

module.exports = {
  mergeStyleHint,
  clampSections,
  buildSpec,
  buildRenderPrompt,
  classifyEdit,
  patchSpec,
  countSpecItems,
  getSpecModel,
};
