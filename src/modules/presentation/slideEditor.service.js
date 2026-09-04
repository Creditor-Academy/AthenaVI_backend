const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const { loadPresentationDeck } = require('./deckGeneration.service');
const { layoutSlotsToElements, blankCanvas, newElementId } = require('./layoutToElements');
const {
  DECK_SLIDE_MAX,
  MAX_ELEMENTS_PER_SLIDE,
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  resolveAspectCanvas,
} = require('./presentation.constants');
const elementCatalog = require('./elements/catalog.json');
const {
  normalizeElement,
  normalizeCanvasDoc,
  enrichSlideForClient,
} = require('./elementContent.normalize');
const {
  canPptGroup,
  canPptUngroup,
  createPptGroup,
  ungroupPptElement,
  alignPptElements,
  collectDeleteIds,
} = require('./elementSelection.ops');

function assertNotGenerating(deck) {
  if (deck.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }
}

function normalizeCanvasPayload(input) {
  const canvas = input?.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  const elements = Array.isArray(input?.elements) ? input.elements : [];
  if (elements.length > MAX_ELEMENTS_PER_SLIDE) {
    throw new AppError(`A slide may have at most ${MAX_ELEMENTS_PER_SLIDE} elements`, 400);
  }
  return normalizeCanvasDoc({
    ...input,
    version: input?.version || 1,
    canvas: {
      width: Number(canvas.width) || CANVAS_WIDTH,
      height: Number(canvas.height) || CANVAS_HEIGHT,
    },
    elements,
  });
}

function getElementsDoc(slide) {
  if (slide.elements && typeof slide.elements === 'object' && Array.isArray(slide.elements.elements)) {
    return {
      ...slide.elements,
      elements: [...slide.elements.elements],
    };
  }
  return blankCanvas();
}

async function loadDeckContext(workspaceId, presentationId) {
  return loadPresentationDeck(presentationId, { requireWorkspaceId: workspaceId });
}

function canvasSizeForDeck(deck) {
  const aspect = resolveAspectCanvas(deck?.aspectRatio);
  return { width: aspect.width, height: aspect.height };
}

async function addSlide({
  workspaceId,
  presentationId,
  afterSlideId,
  beforeSlideId,
  templateId,
  layoutId,
  content,
}) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slides = deck.slides || [];
  if (slides.length >= DECK_SLIDE_MAX) {
    throw new AppError(`Deck may have at most ${DECK_SLIDE_MAX} slides`, 400);
  }

  let insertOrder = slides.length + 1;
  if (beforeSlideId) {
    const before = slides.find((s) => s.id === beforeSlideId);
    if (!before) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
    insertOrder = before.order;
  } else if (afterSlideId) {
    const after = slides.find((s) => s.id === afterSlideId);
    if (!after) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
    insertOrder = after.order + 1;
  }

  let resolvedLayoutId = layoutId || null;
  let contentType = null;
  let layoutSchema = null;

  if (templateId) {
    const template = await presentationDao.findTemplateById(templateId);
    if (!template || template.type !== 'DECK_LAYOUT' || !template.isActive) {
      throw new AppError(messages.PRESENTATION_TEMPLATE_NOT_FOUND, 404);
    }
    layoutSchema = template.schema;
    resolvedLayoutId = template.schema?.layout_id || template.id;
    contentType = template.contentType || template.schema?.content_type || null;
  }

  const slideContent = content && typeof content === 'object' ? content : {};
  const canvasSize = canvasSizeForDeck(deck);
  const elementsDoc = layoutSchema
    ? layoutSlotsToElements(layoutSchema, slideContent, null, canvasSize, {
        themeTokens: deck.themeTokens || null,
        designTokens: slideContent.designTokens || null,
        applyShapes: false,
      })
    : blankCanvas({
        withDefaultText: true,
        width: canvasSize.width,
        height: canvasSize.height,
      });

  await presentationDao.shiftSlideOrders(deck.id, insertOrder, 1);

  const slide = await presentationDao.createOneSlide({
    deckId: deck.id,
    order: insertOrder,
    contentType,
    layoutId: resolvedLayoutId,
    content: slideContent,
    imageRef: null,
    elements: elementsDoc,
    status: 'READY',
    manuallyEdited: true,
  });

  return { slide: enrichSlideForClient(slide), deckId: deck.id };
}

async function deleteSlide({ workspaceId, presentationId, slideId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slides = deck.slides || [];
  const slide = slides.find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  if (slides.length <= 1) {
    throw new AppError('A presentation must keep at least one slide', 400);
  }

  await presentationDao.deleteSlideById(slideId);
  await presentationDao.resequenceSlideOrders(deck.id);

  const updated = await presentationDao.findDeckById(deck.id);
  return { slides: (updated.slides || []).map(enrichSlideForClient), deckId: deck.id };
}

async function duplicateSlide({ workspaceId, presentationId, slideId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slides = deck.slides || [];
  if (slides.length >= DECK_SLIDE_MAX) {
    throw new AppError(`Deck may have at most ${DECK_SLIDE_MAX} slides`, 400);
  }

  const source = slides.find((s) => s.id === slideId);
  if (!source) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const insertOrder = source.order + 1;
  await presentationDao.shiftSlideOrders(deck.id, insertOrder, 1);

  const slide = await presentationDao.createOneSlide({
    deckId: deck.id,
    order: insertOrder,
    contentType: source.contentType,
    layoutId: source.layoutId,
    content: source.content,
    imageRef: source.imageRef,
    elements: source.elements || blankCanvas(canvasSizeForDeck(deck)),
    status: 'READY',
    progressStatus: source.progressStatus ?? null,
    manuallyEdited: true,
  });

  return { slide: enrichSlideForClient(slide), deckId: deck.id };
}

async function reorderSlides({ workspaceId, presentationId, slideIds }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const existing = deck.slides || [];
  if (!Array.isArray(slideIds) || slideIds.length !== existing.length) {
    throw new AppError('slideIds must include every slide id exactly once', 400);
  }
  const set = new Set(existing.map((s) => s.id));
  for (const id of slideIds) {
    if (!set.has(id)) throw new AppError('Unknown slide id in reorder list', 400);
  }
  if (new Set(slideIds).size !== slideIds.length) {
    throw new AppError('Duplicate slide ids in reorder list', 400);
  }

  await presentationDao.reorderSlides(deck.id, slideIds);
  const updated = await presentationDao.findDeckById(deck.id);
  return { slides: (updated.slides || []).map(enrichSlideForClient), deckId: deck.id };
}

async function applyLayout({ workspaceId, presentationId, slideId, templateId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const template = await presentationDao.findTemplateById(templateId);
  if (!template || template.type !== 'DECK_LAYOUT' || !template.isActive) {
    throw new AppError(messages.PRESENTATION_TEMPLATE_NOT_FOUND, 404);
  }

  const content = slide.content && typeof slide.content === 'object' ? slide.content : {};
  const elementsDoc = layoutSlotsToElements(
    template.schema,
    content,
    slide.imageRef,
    canvasSizeForDeck(deck),
    {
      themeTokens: deck.themeTokens || null,
      designTokens: content.designTokens || null,
      applyShapes: false,
    }
  );

  const updated = await presentationDao.updateSlide(slideId, {
    layoutId: template.schema?.layout_id || template.id,
    contentType: template.contentType || template.schema?.content_type || slide.contentType,
    elements: elementsDoc,
    manuallyEdited: true,
    status: 'READY',
  });

  return { slide: enrichSlideForClient(updated) };
}

async function putCanvas({ workspaceId, presentationId, slideId, canvas }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = normalizeCanvasPayload(canvas);
  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  try {
    const { scheduleDeckPreviewRefresh } = require('./deckPreview.service');
    scheduleDeckPreviewRefresh(deck.id);
  } catch {
    // preview refresh is best-effort
  }
  return { slide: enrichSlideForClient(updated) };
}

/**
 * Accept nested `{ element }` or flat FE body fields on the same object.
 */
function resolveIncomingElement({ element, presetId, flat }) {
  let next = element && typeof element === 'object' ? { ...element } : null;
  if (!next && flat && flat.type) {
    next = {
      type: flat.type,
      placement: flat.placement,
      content: flat.content,
      role: flat.role,
      layer: flat.layer,
      presetId: flat.presetId || presetId,
    };
  }
  return { next, presetId: presetId || flat?.presetId || next?.presetId };
}

async function addElement(args) {
  const { workspaceId, presentationId, slideId } = args;
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  if (doc.elements.length >= MAX_ELEMENTS_PER_SLIDE) {
    throw new AppError(`A slide may have at most ${MAX_ELEMENTS_PER_SLIDE} elements`, 400);
  }

  const { next: resolved, presetId } = resolveIncomingElement({
    element: args.element,
    presetId: args.presetId,
    flat: args,
  });

  let next = resolved;
  if (presetId) {
    const preset = elementCatalog.find((p) => p.presetId === presetId);
    if (!preset) throw new AppError('Unknown element preset', 400);
    next = {
      type: next?.type || preset.type,
      layer: doc.elements.length + 1,
      placement: { ...(next?.placement || preset.defaultPlacement) },
      content: { ...(preset.defaultContent || {}), ...(next?.content || {}) },
      role: next?.role || preset.type,
      presetId,
    };
  }

  if (!next || !next.type) {
    throw new AppError('element.type is required', 400);
  }
  next = normalizeElement({
    ...next,
    id: newElementId(),
    placement: next.placement || { x: 200, y: 200, width: 400, height: 200, rotation: 0, opacity: 1 },
    layer: next.layer == null ? doc.elements.length + 1 : next.layer,
  });

  doc.elements.push(next);
  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: enrichSlideForClient(updated), element: next };
}

function persistElementsDoc(slideId, doc) {
  return presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
}

async function patchElement({ workspaceId, presentationId, slideId, elementId, patch }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  const idx = doc.elements.findIndex((e) => e.id === elementId);
  if (idx < 0) throw new AppError('Element not found', 404);

  const current = doc.elements[idx];
  const merged = {
    ...current,
    ...patch,
    id: current.id,
    type: patch.type || current.type,
    placement: patch.placement ? { ...current.placement, ...patch.placement } : current.placement,
    content: patch.content ? { ...current.content, ...patch.content } : current.content,
    locked: patch.locked != null ? Boolean(patch.locked) : current.locked,
  };
  if (patch.childIds) merged.childIds = patch.childIds;
  if (Object.prototype.hasOwnProperty.call(patch, 'groupId')) merged.groupId = patch.groupId;
  doc.elements[idx] = normalizeElement(merged);

  const updated = await persistElementsDoc(slideId, doc);
  return { slide: enrichSlideForClient(updated), element: doc.elements[idx] };
}

async function patchElementsBatch({ workspaceId, presentationId, slideId, patches }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  const byId = new Map(doc.elements.map((el) => [el.id, el]));
  let applied = 0;
  for (const patch of patches || []) {
    const current = byId.get(patch.id);
    if (!current) continue;
    const merged = {
      ...current,
      ...patch,
      id: current.id,
      type: patch.type || current.type,
      placement: patch.placement ? { ...current.placement, ...patch.placement } : current.placement,
      content: patch.content ? { ...current.content, ...patch.content } : current.content,
      locked: patch.locked != null ? Boolean(patch.locked) : current.locked,
    };
    if (patch.childIds) merged.childIds = patch.childIds;
    if (Object.prototype.hasOwnProperty.call(patch, 'groupId')) merged.groupId = patch.groupId;
    byId.set(patch.id, normalizeElement(merged));
    applied += 1;
  }
  if (!applied) throw new AppError('Element not found', 404);

  doc.elements = doc.elements.map((el) => byId.get(el.id) || el);
  const updated = await persistElementsDoc(slideId, doc);
  return { slide: enrichSlideForClient(updated) };
}

async function groupElements({ workspaceId, presentationId, slideId, elementIds }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  if (!canPptGroup(doc.elements, elementIds)) {
    throw new AppError('Select at least two unlocked elements to group', 400);
  }
  if (doc.elements.length + 1 > MAX_ELEMENTS_PER_SLIDE) {
    throw new AppError(`A slide may have at most ${MAX_ELEMENTS_PER_SLIDE} elements`, 400);
  }
  doc.elements = createPptGroup(doc.elements, elementIds).map(normalizeElement);
  const updated = await persistElementsDoc(slideId, doc);
  const group = doc.elements.find((el) => el.type === 'group' && (el.childIds || []).every((id) => elementIds.includes(id)));
  return { slide: enrichSlideForClient(updated), group };
}

async function ungroupElements({ workspaceId, presentationId, slideId, elementId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  if (!canPptUngroup(doc.elements, [elementId])) {
    throw new AppError('Select a group to ungroup', 400);
  }
  doc.elements = ungroupPptElement(doc.elements, elementId).map(normalizeElement);
  const updated = await persistElementsDoc(slideId, doc);
  return { slide: enrichSlideForClient(updated) };
}

async function alignElements({ workspaceId, presentationId, slideId, elementIds, alignment }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  const canvas = doc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  doc.elements = alignPptElements(doc.elements, elementIds, alignment, canvas).map(normalizeElement);
  const updated = await persistElementsDoc(slideId, doc);
  return { slide: enrichSlideForClient(updated) };
}

async function deleteElement({ workspaceId, presentationId, slideId, elementId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  const removeIds = collectDeleteIds(doc.elements, elementId);
  const next = doc.elements
    .filter((e) => !removeIds.has(e.id))
    .map((el) => {
      if (!Array.isArray(el.childIds)) return el;
      const childIds = el.childIds.filter((cid) => !removeIds.has(cid));
      if (childIds.length === el.childIds.length) return el;
      return { ...el, childIds };
    })
    .filter((el) => !(el.type === 'group' && (el.childIds || []).length < 2));
  if (next.length === doc.elements.length) throw new AppError('Element not found', 404);
  doc.elements = next;

  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: enrichSlideForClient(updated) };
}

async function reorderElements({ workspaceId, presentationId, slideId, elementIds }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  if (!Array.isArray(elementIds) || elementIds.length !== doc.elements.length) {
    throw new AppError('elementIds must include every element id exactly once', 400);
  }
  const map = new Map(doc.elements.map((e) => [e.id, e]));
  const ordered = [];
  for (let i = 0; i < elementIds.length; i += 1) {
    const el = map.get(elementIds[i]);
    if (!el) throw new AppError('Unknown element id in reorder list', 400);
    ordered.push({ ...el, layer: i + 1 });
  }
  doc.elements = ordered;

  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: enrichSlideForClient(updated) };
}

function listElementCatalog() {
  const presets = elementCatalog.map((p) => ({
    ...p,
    id: p.presetId,
    presetId: p.presetId,
    content: p.defaultContent,
  }));
  return {
    canvas: { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    presets,
  };
}

const {
  listLayoutCategories,
  resolveCategoryContentTypes,
  categoryIdsForContentType,
} = require('./layoutCategories');

async function listDeckLayouts({ contentType, category } = {}) {
  let typesFilter = null;
  if (category) {
    const resolved = resolveCategoryContentTypes(category);
    if (resolved === undefined) {
      throw new AppError(`Unknown layout category: ${category}`, 400);
    }
    typesFilter = resolved; // null = all
  } else if (contentType) {
    typesFilter = [String(contentType)];
  }

  const rows = await presentationDao.findActiveTemplatesByContentType(
    typesFilter && typesFilter.length ? typesFilter : null
  );
  return {
    categories: listLayoutCategories(),
    templates: rows.map((t) => ({
      id: t.id,
      templateId: t.id,
      name: t.name,
      contentType: t.contentType,
      categories: categoryIdsForContentType(t.contentType),
      variant: t.variant,
      schema: t.schema,
      version: t.version,
      previewUrl: null,
      thumbnailUrl: null,
    })),
  };
}

module.exports = {
  addSlide,
  deleteSlide,
  duplicateSlide,
  reorderSlides,
  applyLayout,
  putCanvas,
  addElement,
  patchElement,
  patchElementsBatch,
  groupElements,
  ungroupElements,
  alignElements,
  deleteElement,
  reorderElements,
  listElementCatalog,
  listDeckLayouts,
  normalizeCanvasPayload,
  getElementsDoc,
};
