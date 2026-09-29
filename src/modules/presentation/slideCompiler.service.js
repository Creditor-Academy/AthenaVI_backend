'use strict';

const {
  layoutSlotsToElements,
  rebindContentToElements,
  applySlideDesignTokens,
  finalizeElementsDoc,
  elementsHaveRebindRoles,
  shouldRecompileLayout,
} = require('./layoutToElements');
const blueprintSeed = require('./blueprintSeed');
const { prepareContentForCompile, isRepairPipelineEnabled } = require('./contentRepair.service');
const { recordContentRepairAudit } = require('./contentRepairAudit');

function compiledHasWeakRequiredText(elementsDoc) {
  return (elementsDoc?.elements || []).some((el) => {
    if (el.type !== 'text' && el.type !== 'textbox') return false;
    const role = String(el.role || '').toLowerCase();
    if (!['heading', 'title', 'subheading', 'subtitle', 'body', 'bullet'].includes(role)) return false;
    return blueprintSeed.isWeakText(el.content?.text);
  });
}

/**
 * Pre-compile repair + layoutSlotsToElements + finalize.
 */
async function compileSlide({
  layoutSchema,
  content,
  imageRef = null,
  canvasSize = {},
  themeTokens = null,
  designTokens = null,
  rebindBase = null,
  forceTextReplace = false,
  slideDesignPlan = null,
  outlineSlide = null,
  skipContentRepair = false,
  context = {},
}) {
  let workingContent = content && typeof content === 'object' ? content : {};
  let audit = { warnings: [], repairs: [], issues: [], passes: 0, durationMs: 0, skipped: true };

  if (!skipContentRepair && isRepairPipelineEnabled() && layoutSchema?.slots?.length) {
    const prepared = await prepareContentForCompile({
      content: workingContent,
      layoutSchema,
      context,
    });
    workingContent = prepared.content;
    audit = prepared.audit;
  }

  const canvas = {
    width: canvasSize.width || 1920,
    height: canvasSize.height || 1080,
  };

  const compileAgainst =
    context.currentElements && typeof context.currentElements === 'object'
      ? context.currentElements
      : rebindBase;
  const useFreshCompile =
    Boolean(layoutSchema?.slots?.length) &&
    (context.packBound || shouldRecompileLayout(layoutSchema, compileAgainst));

  let elementsDoc;
  if (rebindBase && !useFreshCompile) {
    elementsDoc = rebindContentToElements(rebindBase, workingContent, imageRef, {
      forceTextReplace: Boolean(forceTextReplace),
      themeTokens,
      layoutSchema,
    });
    elementsDoc = applySlideDesignTokens(elementsDoc, designTokens, themeTokens);
  } else if (layoutSchema?.slots?.length) {
    elementsDoc = layoutSlotsToElements(layoutSchema, workingContent, imageRef, canvas, {
      themeTokens,
      designTokens,
      applyShapes: false,
    });
  } else if (rebindBase) {
    elementsDoc = rebindContentToElements(rebindBase, workingContent, imageRef, {
      forceTextReplace: Boolean(forceTextReplace),
      themeTokens,
      layoutSchema,
    });
    elementsDoc = applySlideDesignTokens(elementsDoc, designTokens, themeTokens);
  } else {
    elementsDoc = layoutSlotsToElements({ slots: [] }, workingContent, imageRef, canvas, {
      themeTokens,
      designTokens,
      applyShapes: false,
    });
  }

  elementsDoc = finalizeElementsDoc(
    elementsDoc,
    layoutSchema,
    workingContent,
    themeTokens,
    canvas,
    slideDesignPlan
  );

  let emptySlotFallback = false;
  if (compiledHasWeakRequiredText(elementsDoc) && layoutSchema?.slots?.length && outlineSlide) {
    workingContent = blueprintSeed.mergeSeedIntoContent(
      workingContent,
      blueprintSeed.seedFromOutlineSlide(outlineSlide),
      layoutSchema
    );
    elementsDoc = layoutSlotsToElements(layoutSchema, workingContent, imageRef, canvas, {
      themeTokens,
      designTokens,
      applyShapes: false,
    });
    elementsDoc = finalizeElementsDoc(
      elementsDoc,
      layoutSchema,
      workingContent,
      themeTokens,
      canvas,
      slideDesignPlan
    );
    emptySlotFallback = true;
  }

  if (context.slideId) {
    await recordContentRepairAudit({
      slideId: context.slideId,
      deckId: context.deckId,
      layoutId: layoutSchema?.layout_id || layoutSchema?.layoutId,
      phase: 'COMPILE',
      audit: { ...audit, emptySlotFallback },
    });
  }

  return { elementsDoc, content: workingContent, audit, emptySlotFallback };
}

module.exports = {
  compileSlide,
  compiledHasWeakRequiredText,
};
