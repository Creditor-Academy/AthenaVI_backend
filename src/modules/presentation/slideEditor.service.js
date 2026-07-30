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
} = require('./presentation.constants');
const elementCatalog = require('./elements/catalog.json');

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
  return {
    version: input?.version || 1,
    canvas: {
      width: Number(canvas.width) || CANVAS_WIDTH,
      height: Number(canvas.height) || CANVAS_HEIGHT,
    },
    elements,
  };
}

function getElementsDoc(slide) {
  if (slide.elements && typeof slide.elements === 'object' && Array.isArray(slide.elements.elements)) {
    return slide.elements;
  }
  return blankCanvas();
}

async function loadDeckContext(workspaceId, presentationId) {
  return loadPresentationDeck(presentationId, { requireWorkspaceId: workspaceId });
}

async function addSlide({
  workspaceId,
  presentationId,
  afterSlideId,
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
  if (afterSlideId) {
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
  const elementsDoc = layoutSchema
    ? layoutSlotsToElements(layoutSchema, slideContent, null)
    : blankCanvas({ withDefaultText: true });

  // Shift orders for slides at/after insert position
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

  return { slide, deckId: deck.id };
}

async function deleteSlide({ workspaceId, presentationId, slideId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  await presentationDao.deleteSlideById(slideId);
  await presentationDao.resequenceSlideOrders(deck.id);

  const updated = await presentationDao.findDeckById(deck.id);
  return { slides: updated.slides || [], deckId: deck.id };
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
    elements: source.elements || blankCanvas(),
    status: 'READY',
    manuallyEdited: true,
  });

  return { slide, deckId: deck.id };
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
  return { slides: updated.slides || [], deckId: deck.id };
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
  const elementsDoc = layoutSlotsToElements(template.schema, content, slide.imageRef);

  const updated = await presentationDao.updateSlide(slideId, {
    layoutId: template.schema?.layout_id || template.id,
    contentType: template.contentType || template.schema?.content_type || slide.contentType,
    elements: elementsDoc,
    manuallyEdited: true,
    status: 'READY',
  });

  return { slide: updated };
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
  return { slide: updated };
}

async function addElement({ workspaceId, presentationId, slideId, element, presetId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  if (doc.elements.length >= MAX_ELEMENTS_PER_SLIDE) {
    throw new AppError(`A slide may have at most ${MAX_ELEMENTS_PER_SLIDE} elements`, 400);
  }

  let next = element && typeof element === 'object' ? { ...element } : null;
  if (presetId) {
    const preset = elementCatalog.find((p) => p.presetId === presetId);
    if (!preset) throw new AppError('Unknown element preset', 400);
    next = {
      type: preset.type,
      layer: doc.elements.length + 1,
      placement: { ...(next?.placement || preset.defaultPlacement) },
      content: { ...(preset.defaultContent || {}), ...(next?.content || {}) },
      role: next?.role || preset.type,
    };
  }

  if (!next || !next.type) {
    throw new AppError('element.type is required', 400);
  }
  next.id = newElementId();
  if (!next.placement) {
    next.placement = { x: 200, y: 200, width: 400, height: 200, rotation: 0, opacity: 1 };
  }
  if (next.layer == null) next.layer = doc.elements.length + 1;

  doc.elements.push(next);
  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: updated, element: next };
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
  doc.elements[idx] = {
    ...current,
    ...patch,
    id: current.id,
    placement: patch.placement ? { ...current.placement, ...patch.placement } : current.placement,
    content: patch.content ? { ...current.content, ...patch.content } : current.content,
  };

  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: updated, element: doc.elements[idx] };
}

async function deleteElement({ workspaceId, presentationId, slideId, elementId }) {
  const { deck } = await loadDeckContext(workspaceId, presentationId);
  assertNotGenerating(deck);

  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);

  const doc = getElementsDoc(slide);
  const next = doc.elements.filter((e) => e.id !== elementId);
  if (next.length === doc.elements.length) throw new AppError('Element not found', 404);
  doc.elements = next;

  const updated = await presentationDao.updateSlide(slideId, {
    elements: doc,
    manuallyEdited: true,
    status: 'READY',
  });
  return { slide: updated };
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
  return { slide: updated };
}

function listElementCatalog() {
  return {
    canvas: { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    presets: elementCatalog,
  };
}

async function listDeckLayouts({ contentType } = {}) {
  const rows = await presentationDao.findActiveTemplatesByContentType(contentType || null);
  return rows.map((t) => ({
    id: t.id,
    name: t.name,
    contentType: t.contentType,
    variant: t.variant,
    schema: t.schema,
    version: t.version,
  }));
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
  deleteElement,
  reorderElements,
  listElementCatalog,
  listDeckLayouts,
  normalizeCanvasPayload,
  getElementsDoc,
};
