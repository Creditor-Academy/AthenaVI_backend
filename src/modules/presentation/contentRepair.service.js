'use strict';

const {
  repairContentForLayoutDetailed,
  validateContentForLayoutSoft,
  collectRawArrayOverflowErrors,
} = require('@athena/contracts/contentContract.js');
const { runContentPreShape } = require('./contentPreShape.util');
const { validateSlide } = require('./layoutQa.service');
const { applyHeuristicRepairs } = require('./contentRepairHeuristics');
const { recordContentRepairAudit } = require('./contentRepairAudit');

const MAX_PASSES = Number(process.env.PPT_CONTENT_REPAIR_PASSES) > 0
  ? Number(process.env.PPT_CONTENT_REPAIR_PASSES)
  : 3;

function isRepairPipelineEnabled() {
  if (process.env.PPT_CONTENT_REPAIR_PIPELINE === 'false') return false;
  return true;
}

function mergeIssues(...lists) {
  const out = [];
  const seen = new Set();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const issue of list) {
      const key = `${issue.source || ''}:${issue.code || issue.rule || ''}:${issue.path || issue.slotId || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(issue);
    }
  }
  return out;
}

function hasUnresolvedOverflow(issues) {
  return (issues || []).some(
    (i) => String(i.code || '') === 'ARRAY_OVERFLOW' && i.repairable === false
  );
}

function hasRepairableIssues(issues) {
  if (hasUnresolvedOverflow(issues)) return false;
  return (issues || []).some(
    (i) =>
      i.repairable === true ||
      (i.source === 'contract' && String(i.code || '') !== 'ARRAY_OVERFLOW') ||
      (String(i.code || '').startsWith('ARRAY_') && i.repairable !== false) ||
      String(i.code || '') === 'MISSING_TITLE' ||
      String(i.code || '') === 'JOI_VALIDATION'
  );
}

function rawOverflowIssues(rawContent, layoutSchema) {
  return collectRawArrayOverflowErrors(rawContent, layoutSchema).map((err) => ({
    ...err,
    source: 'contract',
    repairable: false,
    requiresLayoutRetry: true,
    phase: 'raw',
  }));
}

/**
 * Normalize → validate → repair loop before layout compilation.
 */
async function prepareContentForCompile({ content, layoutSchema, context = {} }) {
  const started = Date.now();

  if (!isRepairPipelineEnabled() || !layoutSchema?.slots?.length) {
    return {
      content: content && typeof content === 'object' ? content : {},
      audit: { warnings: [], repairs: [], issues: [], passes: 0, durationMs: 0, skipped: true },
    };
  }

  const rawContent =
    content && typeof content === 'object'
      ? JSON.parse(JSON.stringify(content))
      : {};
  let next = JSON.parse(JSON.stringify(rawContent));
  const allRepairs = [];
  const warnings = [];
  let passes = 0;
  let issues = rawOverflowIssues(rawContent, layoutSchema);
  const skipClampRepeatingGroups = issues.length > 0;

  next = runContentPreShape(next, layoutSchema);

  if (skipClampRepeatingGroups) {
    const qa = validateSlide({
      content: next,
      layoutSchema,
      includeContract: true,
      contractPhase: 'repaired',
      rawOverflowSource: rawContent,
    });
    issues = mergeIssues(rawOverflowIssues(rawContent, layoutSchema), qa.issues);
    warnings.push('ARRAY_OVERFLOW_UNRESOLVED');
    const durationMs = Date.now() - started;
    const audit = {
      warnings: [...new Set(warnings)],
      repairs: allRepairs,
      issues,
      passes: 0,
      durationMs,
      rawOverflowBlocked: true,
    };
    if (context.slideId) {
      await recordContentRepairAudit({
        slideId: context.slideId,
        deckId: context.deckId,
        layoutId: String(layoutSchema?.layout_id || layoutSchema?.layoutId || ''),
        phase: 'PRE_COMPILE',
        audit,
      });
    }
    return { content: next, audit };
  }

  for (passes = 0; passes < MAX_PASSES; passes += 1) {
    const repaired = repairContentForLayoutDetailed(next, layoutSchema, {
      skipClampRepeatingGroups,
    });
    next = repaired.content;
    allRepairs.push(...(repaired.repairs || []));
    warnings.push(...(repaired.warnings || []));

    const contractVal = validateContentForLayoutSoft(next, layoutSchema);
    const qa = validateSlide({
      content: next,
      layoutSchema,
      includeContract: true,
      contractPhase: 'repaired',
      rawOverflowSource: rawContent,
    });
    next = qa.content;
    issues = mergeIssues(
      rawOverflowIssues(rawContent, layoutSchema),
      contractVal.errors.map((e) => ({ ...e, source: 'contract', repairable: true })),
      qa.issues
    );

    if (!hasRepairableIssues(issues)) break;

    const heur = applyHeuristicRepairs(next, layoutSchema, issues);
    next = heur.content;
    allRepairs.push(...(heur.repairs || []));
  }

  const finalRepair = repairContentForLayoutDetailed(next, layoutSchema, {
    skipClampRepeatingGroups,
  });
  next = finalRepair.content;
  allRepairs.push(...(finalRepair.repairs || []));

  const finalContract = validateContentForLayoutSoft(next, layoutSchema);
  const finalQa = validateSlide({
    content: next,
    layoutSchema,
    includeContract: true,
    contractPhase: 'repaired',
    rawOverflowSource: rawContent,
  });
  next = finalQa.content;
  issues = mergeIssues(
    rawOverflowIssues(rawContent, layoutSchema),
    finalContract.errors.map((e) => ({ ...e, source: 'contract', repairable: true })),
    finalQa.issues
  );

  if (hasUnresolvedOverflow(issues)) {
    warnings.push('ARRAY_OVERFLOW_UNRESOLVED');
  }

  const durationMs = Date.now() - started;
  const audit = {
    warnings: [...new Set(warnings)],
    repairs: allRepairs,
    issues,
    passes: passes + 1,
    durationMs,
    rawOverflowBlocked: skipClampRepeatingGroups,
  };

  const slideId = context.slideId || null;
  const deckId = context.deckId || null;
  const layoutId = String(layoutSchema?.layout_id || layoutSchema?.layoutId || '');
  if (slideId) {
    await recordContentRepairAudit({
      slideId,
      deckId,
      layoutId,
      phase: 'PRE_COMPILE',
      audit,
    });
  }

  return { content: next, audit };
}

module.exports = {
  prepareContentForCompile,
  isRepairPipelineEnabled,
};
