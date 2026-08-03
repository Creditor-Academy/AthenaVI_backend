const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const themeService = require('./theme.service');
const deckGeneration = require('./deckGeneration.service');
const exportService = require('./export.service');
const slideEditorRaw = require('./slideEditor.service');
const { layoutSlotsToElements, blankCanvas, injectBrandLogo } = require('./layoutToElements');
const brandKitService = require('../brandKit/brandKit.service');
const {
  attachPresignedMediaToSlides,
  presignPresentationPayload,
} = require('./presignSlideMedia');
const { CANVAS_BY_ASPECT } = require('./generationFlow.service');

const SLIDE_EDITOR_PASSTHROUGH = new Set([
  'listElementCatalog',
  'listDeckLayouts',
  'normalizeCanvasPayload',
  'getElementsDoc',
]);

const slideEditor = Object.fromEntries(
  Object.entries(slideEditorRaw).map(([key, value]) => {
    if (typeof value !== 'function' || SLIDE_EDITOR_PASSTHROUGH.has(key)) {
      return [key, value];
    }
    return [
      key,
      async (...args) => presignPresentationPayload(await value(...args)),
    ];
  })
);

async function resolveCreateThemeTokens({
  workspaceId,
  themeId,
  themeTokens,
  brandKitId,
  packThemeId,
}) {
  if (brandKitId) {
    return brandKitService.loadKitThemeTokens(workspaceId, brandKitId);
  }
  return themeService.resolveThemeTokens({
    themeId: themeId || packThemeId || null,
    themeTokens,
  });
}

function canvasForAspect(aspectRatio) {
  return CANVAS_BY_ASPECT[aspectRatio] || CANVAS_BY_ASPECT['16:9'];
}

async function createPresentation({
  workspaceId,
  userId,
  folderId,
  name,
  title,
  themeId,
  themeTokens,
  locale = 'en',
  aspectRatio = '16:9',
  createMode = 'blank',
  templateId = null,
  packId = null,
  brandKitId = null,
}) {
  const folder = await prisma.folder.findFirst({
    where: { id: folderId, workspaceId },
    select: { id: true, workspaceId: true },
  });
  if (!folder) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }

  const mode =
    createMode === 'template' ? 'template' : createMode === 'pack' ? 'pack' : 'blank';
  if (mode === 'template' && !templateId) {
    throw new AppError('templateId is required when createMode is template', 400);
  }
  if (mode === 'pack' && !packId) {
    throw new AppError('packId is required when createMode is pack', 400);
  }

  let template = null;
  let pack = null;
  if (mode === 'template') {
    template = await presentationDao.findTemplateById(templateId);
    if (!template || template.type !== 'DECK_LAYOUT' || !template.isActive) {
      throw new AppError(messages.PRESENTATION_TEMPLATE_NOT_FOUND, 404);
    }
  }
  if (mode === 'pack') {
    pack = await presentationDao.findTemplateById(packId);
    if (!pack || pack.type !== 'DECK_PACK' || !pack.isActive) {
      throw new AppError(messages.PRESENTATION_DECK_PACK_NOT_FOUND, 404);
    }
  }

  const packAspect = pack?.schema?.aspectRatio || aspectRatio;
  const resolvedTokens = await resolveCreateThemeTokens({
    workspaceId,
    themeId,
    themeTokens,
    brandKitId,
    packThemeId: pack?.schema?.themeId || null,
  });
  const displayName = String(name || title || 'Untitled Presentation').trim() || 'Untitled Presentation';

  const { project, deck } = await presentationDao.createPresentationProject({
    workspaceId,
    folderId,
    name: displayName,
    createdBy: userId,
    themeTokens: resolvedTokens,
    aspectRatio: packAspect || aspectRatio,
    locale,
  });

  const metricsBase = {
    ...(deck.generationMetrics && typeof deck.generationMetrics === 'object'
      ? deck.generationMetrics
      : {}),
  };
  if (pack) {
    metricsBase.deckPack = {
      packId: pack.id,
      pack_id: pack.schema?.pack_id || null,
      brandKitId: brandKitId || null,
    };
  } else if (brandKitId) {
    metricsBase.deckPack = { packId: null, brandKitId };
  }
  if (Object.keys(metricsBase).length) {
    await presentationDao.updateDeck(deck.id, { generationMetrics: metricsBase });
  }

  let slides = deck.slides || [];
  const canvasSize = canvasForAspect(packAspect || aspectRatio);
  const logo = brandKitService.pickLogoForBackground(resolvedTokens);

  if (mode === 'template' && template) {
    let elementsDoc = layoutSlotsToElements(
      template.schema,
      { title: displayName },
      null,
      canvasSize,
      { themeTokens: resolvedTokens }
    );
    elementsDoc = injectBrandLogo(elementsDoc, logo, {
      contentType: template.contentType || template.schema?.content_type,
    });
    const slide = await presentationDao.createOneSlide({
      deckId: deck.id,
      order: 1,
      contentType: template.contentType || template.schema?.content_type || null,
      layoutId: template.schema?.layout_id || template.id,
      content: { title: displayName },
      imageRef: null,
      elements: elementsDoc,
      status: 'READY',
      manuallyEdited: true,
    });
    slides = [slide];
  }

  if (mode === 'pack' && pack) {
    const packSlides = Array.isArray(pack.schema?.slides) ? pack.schema.slides : [];
    const layoutIds = packSlides.map((s) => s.layout_id);
    const layouts = await presentationDao.findLayoutsByLayoutIds(layoutIds);
    const byLayoutId = new Map(layouts.map((l) => [l.schema?.layout_id, l]));

    const slidePayloads = packSlides.map((ps) => {
      const layout = byLayoutId.get(ps.layout_id);
      if (!layout) {
        throw new AppError(
          `Pack references missing layout_id: ${ps.layout_id}`,
          400
        );
      }
      const placeholder = {
        title: displayName,
        ...(ps.placeholder && typeof ps.placeholder === 'object' ? ps.placeholder : {}),
      };
      if (!placeholder.title) placeholder.title = displayName;
      let elementsDoc = layoutSlotsToElements(
        layout.schema,
        placeholder,
        null,
        canvasSize,
        {
          themeTokens: resolvedTokens,
          designTokens: ps.designTokens || null,
        }
      );
      elementsDoc = injectBrandLogo(elementsDoc, logo, {
        contentType: ps.contentType || layout.contentType,
      });
      return {
        order: ps.order,
        contentType: ps.contentType || layout.contentType || null,
        layoutId: layout.schema?.layout_id || layout.id,
        content: {
          ...placeholder,
          intent: ps.intent || null,
          designTokens: ps.designTokens || null,
          generationHints: ps.generationHints || null,
        },
        imageRef: null,
        elements: elementsDoc,
        status: 'READY',
        manuallyEdited: true,
      };
    });

    slides = await presentationDao.createSlides(deck.id, slidePayloads);
  }

  const refreshed = await presentationDao.findDeckById(deck.id);
  const outDeck = refreshed || { ...deck, slides };
  const signedSlides = await attachPresignedMediaToSlides(outDeck.slides || slides);
  return {
    project,
    deck: { ...outDeck, slides: signedSlides },
    slides: signedSlides,
  };
}

async function listPresentationDeckPacks() {
  const packs = await presentationDao.findActiveDeckPacks();
  return packs.map((p) => ({
    id: p.id,
    name: p.name,
    packId: p.schema?.pack_id || p.id,
    themeId: p.schema?.themeId || null,
    aspectRatio: p.schema?.aspectRatio || '16:9',
    slideCount: Array.isArray(p.schema?.slides) ? p.schema.slides.length : 0,
    meta: p.schema?.meta || null,
    narrative: p.schema?.narrative || null,
    preview: p.schema?.preview || null,
    generationDefaults: p.schema?.generationDefaults || null,
    variant: p.variant,
    version: p.version,
  }));
}

async function applyBrandKit({ workspaceId, presentationId, brandKitId }) {
  const { deck } = await deckGeneration.loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  if (deck.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }

  const themeTokens = await brandKitService.loadKitThemeTokens(workspaceId, brandKitId);
  const logo = brandKitService.pickLogoForBackground(themeTokens);
  const metrics = {
    ...(deck.generationMetrics && typeof deck.generationMetrics === 'object'
      ? deck.generationMetrics
      : {}),
    deckPack: {
      ...((deck.generationMetrics && deck.generationMetrics.deckPack) || {}),
      brandKitId,
    },
  };

  const updatedSlides = [];
  for (const slide of deck.slides || []) {
    const elements = injectBrandLogo(slide.elements, logo, {
      contentType: slide.contentType,
      force: Boolean(slide.elements?.elements?.some((e) => e?.role === 'logo')),
    });
    const updated = await presentationDao.updateSlide(slide.id, { elements });
    updatedSlides.push(updated);
  }

  const updatedDeck = await presentationDao.updateDeck(deck.id, {
    themeTokens,
    generationMetrics: metrics,
  });

  return {
    deck: {
      id: updatedDeck.id,
      projectId: updatedDeck.projectId,
      themeTokens: updatedDeck.themeTokens,
      generationMetrics: updatedDeck.generationMetrics,
      status: updatedDeck.status,
      aspectRatio: updatedDeck.aspectRatio,
    },
    slides: await attachPresignedMediaToSlides(updatedSlides),
  };
}

async function getPresentation(workspaceId, presentationId) {
  const { deck, project } = await deckGeneration.loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  const fullProject = await prisma.project.findFirst({
    where: { id: presentationId, workspaceId },
    include: {
      folder: { select: { id: true, name: true } },
    },
  });

  return {
    project: fullProject || project,
    deck: {
      id: deck.id,
      projectId: deck.projectId,
      themeTokens: deck.themeTokens,
      outline: deck.outline,
      status: deck.status,
      aspectRatio: deck.aspectRatio,
      locale: deck.locale,
      promptBundleVersion: deck.promptBundleVersion,
      generationMetrics: deck.generationMetrics,
      partial: deck.partial,
      creditsChargedSoFar: deck.creditsChargedSoFar,
      createdAt: deck.createdAt,
      updatedAt: deck.updatedAt,
    },
    slides: await attachPresignedMediaToSlides(deck.slides || []),
  };
}

async function creditEstimate({ workspaceId, presentationId, slideCount }) {
  const { deck } = await deckGeneration.loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  const count =
    slideCount != null
      ? Number(slideCount)
      : Array.isArray(deck.outline?.slides)
        ? deck.outline.slides.length
        : deck.outline?.slideCount || 12;

  const outline = presentationCredit.estimateOutlineAc();
  const generate = presentationCredit.estimateGenerateCost(count);
  const exportAc = presentationCredit.getFlatAc(presentationCredit.PPT_FEATURE.EXPORT);

  return {
    slideCount: count,
    outline,
    generate,
    export: {
      athenaCredits: exportAc,
      feature: presentationCredit.PPT_FEATURE.EXPORT,
    },
    totalEstimatedCredits: outline.athenaCredits + generate.athenaCredits + exportAc,
  };
}

async function addSlide({
  workspaceId,
  presentationId,
  userId,
  afterSlideId,
  templateId,
  layoutId,
  content,
  generate = false,
  prompt = null,
  target = 'all',
}) {
  const created = await slideEditor.addSlide({
    workspaceId,
    presentationId,
    afterSlideId,
    templateId,
    layoutId,
    content,
  });

  if (!generate) {
    return created;
  }

  const promptText =
    (prompt != null && String(prompt).trim()) ||
    (content && content.title && String(content.title).trim()) ||
    null;

  const regen = await deckGeneration.regenerateSlide({
    workspaceId,
    presentationId,
    slideId: created.slide.id,
    userId,
    target: target || 'all',
    overwriteManualEdits: true,
    prompt: promptText,
  });

  return {
    ...created,
    status: regen.status,
    target: regen.target,
    estimatedCredits: regen.estimatedCredits,
  };
}

module.exports = {
  createPresentation,
  getPresentation,
  creditEstimate,
  listPresentationDeckPacks,
  applyBrandKit,
  generateOutline: deckGeneration.generateOutline,
  updateOutline: deckGeneration.updateOutline,
  setTheme: deckGeneration.setTheme,
  startGenerate: deckGeneration.startGenerate,
  getStatus: deckGeneration.getStatus,
  regenerateSlide: deckGeneration.regenerateSlide,
  patchSlide: async (...args) =>
    presignPresentationPayload(await deckGeneration.patchSlide(...args)),
  queueExport: exportService.queueExport,
  getExport: exportService.getExport,
  listThemes: themeService.listThemes,
  ...slideEditor,
  addSlide,
  blankCanvas,
};
