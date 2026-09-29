'use strict';

const {
  repairContentForLayoutDetailed,
  validateContentForLayoutSoft,
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

function hasRepairableIssues(issues) {
  return (issues || []).some(
    (i) =>
      i.repairable === true ||
      i.source === 'contract' ||
      String(i.code || '').startsWith('ARRAY_') ||
      String(i.code || '') === 'MISSING_TITLE' ||
      String(i.code || '') === 'JOI_VALIDATION'
  );
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

  let next =
    content && typeof content === 'object'
      ? JSON.parse(JSON.stringify(content))
      : {};
  const allRepairs = [];
  const warnings = [];
  let passes = 0;
  let issues = [];

  next = runContentPreShape(next, layoutSchema);

  for (passes = 0; passes < MAX_PASSES; passes += 1) {
    const repaired = repairContentForLayoutDetailed(next, layoutSchema);
    next = repaired.content;
    allRepairs.push(...(repaired.repairs || []));
    warnings.push(...(repaired.warnings || []));

    const contractVal = validateContentForLayoutSoft(next, layoutSchema);
    const qa = validateSlide({
      content: next,
      layoutSchema,
      includeContract: true,
      contractPhase: 'repaired',
    });
    next = qa.content;
    issues = mergeIssues(
      contractVal.errors.map((e) => ({ ...e, source: 'contract', repairable: true })),
      qa.issues
    );

    if (!hasRepairableIssues(issues)) break;

    const heur = applyHeuristicRepairs(next, layoutSchema, issues);
    next = heur.content;
    allRepairs.push(...(heur.repairs || []));
  }

  const finalRepair = repairContentForLayoutDetailed(next, layoutSchema);
  next = finalRepair.content;
  allRepairs.push(...(finalRepair.repairs || []));

  const finalContract = validateContentForLayoutSoft(next, layoutSchema);
  const finalQa = validateSlide({
    content: next,
    layoutSchema,
    includeContract: true,
    contractPhase: 'repaired',
  });
  next = finalQa.content;
  issues = mergeIssues(
    finalContract.errors.map((e) => ({ ...e, source: 'contract', repairable: true })),
    finalQa.issues
  );

  const durationMs = Date.now() - started;
  const audit = {
    warnings: [...new Set(warnings)],
    repairs: allRepairs,
    issues,
    passes: passes + 1,
    durationMs,
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
