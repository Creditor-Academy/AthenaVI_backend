const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const themeService = require('./theme.service');
const deckGeneration = require('./deckGeneration.service');
const exportService = require('./export.service');
const slideEditorRaw = require('./slideEditor.service');
const { layoutSlotsToElements, blankCanvas, injectBrandLogo, rebindContentToElements } = require('./layoutToElements');
const brandKitService = require('../brandKit/brandKit.service');
const templateMediaService = require('../templates/templateMedia.service');
const deckPackGalleryService = require('./deckPackGallery.service');
const templateMediaDao = require('../templates/templateMedia.dao');
const {
  attachPresignedMediaToSlides,
  presignPresentationPayload,
} = require('./presignSlideMedia');
const { CANVAS_BY_ASPECT } = require('./generationFlow.service');
const { enrichSlidesForClient } = require('./elementContent.normalize');
const { enrichProjects } = require('../project/project.format');
const projectDao = require('../project/project.dao');

function withFlatPresentationFields({ project, deck, slides }) {
  const proj = project || {};
  const d = deck || {};
  return {
    project: proj,
    deck: d,
    slides,
    id: proj.id || d.projectId,
    title: proj.name,
    status: d.status,
    themeTokens: d.themeTokens,
    aspectRatio: d.aspectRatio,
    locale: d.locale,
    folderId: proj.folderId,
  };
}

async function assertFolderInWorkspace(folderId, workspaceId) {
  const folder = await projectDao.findFolderById(folderId);
  if (!folder || folder.workspaceId !== workspaceId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }
  return folder;
}

async function listPresentations({ workspaceId, folderId }) {
  if (folderId) {
    await assertFolderInWorkspace(folderId, workspaceId);
  }

  const rows = await presentationDao.listPresentations({ workspaceId, folderId });
  const enriched = await enrichProjects(rows, { includeData: false });

  return enriched.map((project, index) => {
    const deck = rows[index]?.deck || null;
    return {
      ...project,
      title: project.name,
      deckId: deck?.id || null,
      deckStatus: deck?.status || null,
      aspectRatio: deck?.aspectRatio || null,
      locale: deck?.locale || null,
      partial: deck?.partial ?? false,
      slideCount: deck?._count?.slides ?? 0,
    };
  });
}

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
  const { themeTokens: kitTokens, brandKitId: resolvedKitId } =
    await brandKitService.loadKitThemeTokensResolved(workspaceId, brandKitId);
  if (kitTokens) {
    return { themeTokens: kitTokens, brandKitId: resolvedKitId };
  }
  return {
    themeTokens: themeService.resolveThemeTokens({
      themeId: themeId || packThemeId || null,
      themeTokens,
    }),
    brandKitId: null,
  };
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

  const packAspectRaw = String(pack?.schema?.aspectRatio || aspectRatio || '16:9').trim();
  const resolvedAspect = packAspectRaw === '4:3' ? '4:3' : '16:9';
  const { themeTokens: resolvedTokens, brandKitId: effectiveBrandKitId } =
    await resolveCreateThemeTokens({
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
    aspectRatio: resolvedAspect,
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
      brandKitId: effectiveBrandKitId || brandKitId || null,
    };
  } else if (effectiveBrandKitId || brandKitId) {
    metricsBase.deckPack = { packId: null, brandKitId: effectiveBrandKitId || brandKitId };
  }
  if (Object.keys(metricsBase).length) {
    await presentationDao.updateDeck(deck.id, { generationMetrics: metricsBase });
  }

  let slides = deck.slides || [];
  const canvasSize = canvasForAspect(resolvedAspect);
  const logo = brandKitService.pickLogoForBackground(resolvedTokens);

  if (mode === 'blank') {
    let elementsDoc = blankCanvas({
      width: canvasSize.width,
      height: canvasSize.height,
      withDefaultText: true,
    });
    elementsDoc = injectBrandLogo(elementsDoc, logo, { contentType: 'title', force: true });
    const slide = await presentationDao.createOneSlide({
      deckId: deck.id,
      order: 1,
      contentType: null,
      layoutId: null,
      content: { title: displayName },
      imageRef: null,
      elements: elementsDoc,
      status: 'READY',
      manuallyEdited: false,
    });
    slides = [slide];
  }

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
    const layoutIds = packSlides.map((s) => s.layout_id).filter(Boolean);
    const layouts = layoutIds.length
      ? await presentationDao.findLayoutsByLayoutIds(layoutIds)
      : [];
    const byLayoutId = new Map(layouts.map((l) => [l.schema?.layout_id, l]));

    const packMediaRows = await templateMediaDao.listByTemplateId(pack.id);
    const mediaByHint = new Map(
      (packMediaRows || []).filter((m) => m.slotHint).map((m) => [m.slotHint, m])
    );

    const slidePayloads = [];
    for (const ps of packSlides) {
      const layout = ps.layout_id ? byLayoutId.get(ps.layout_id) : null;
      const hasSnapshot = Boolean(ps.snapshot?.elements);
      if (!layout && !hasSnapshot) {
        throw new AppError(
          `Pack references missing layout_id: ${ps.layout_id || '(none)'}`,
          400
        );
      }
      const placeholder = {
        title: displayName,
        ...(ps.placeholder && typeof ps.placeholder === 'object' ? ps.placeholder : {}),
      };
      if (!placeholder.title) placeholder.title = displayName;

      const imageRef = await templateMediaService.resolvePackSlideImageRef({
        packTemplateId: pack.id,
        slideOrder: ps.order,
        placeholder,
        mediaByHint,
      });
      if (imageRef?.s3Key && !placeholder.imageS3Key) {
        placeholder.imageS3Key = imageRef.s3Key;
      }
      if (imageRef?.url) {
        placeholder.imageUrls = [imageRef.url];
      }

      let elementsDoc;
      if (hasSnapshot) {
        elementsDoc = JSON.parse(JSON.stringify(ps.snapshot.elements));
        if (!elementsDoc.canvas) {
          elementsDoc.canvas = { width: canvasSize.width, height: canvasSize.height };
        }
        if (imageRef?.url || imageRef?.s3Key) {
          elementsDoc = rebindContentToElements(elementsDoc, placeholder, imageRef);
        }
      } else {
        elementsDoc = layoutSlotsToElements(
          layout.schema,
          placeholder,
          imageRef,
          canvasSize,
          {
            themeTokens: resolvedTokens,
            designTokens: ps.designTokens || null,
          }
        );
      }
      elementsDoc = injectBrandLogo(elementsDoc, logo, {
        contentType: ps.contentType || layout?.contentType,
      });
      slidePayloads.push({
        order: ps.order,
        contentType: ps.contentType || layout?.contentType || null,
        layoutId: layout?.schema?.layout_id || layout?.id || ps.layout_id || null,
        content: {
          ...placeholder,
          intent: ps.intent || null,
          designTokens: ps.designTokens || null,
          generationHints: ps.generationHints || null,
        },
        imageRef: imageRef || null,
        elements: elementsDoc,
        status: 'READY',
        manuallyEdited: true,
      });
    }

    slides = await presentationDao.createSlides(deck.id, slidePayloads);
  }

  const refreshed = await presentationDao.findDeckById(deck.id);
  const outDeck = refreshed || { ...deck, slides };
  const signedSlides = enrichSlidesForClient(
    await attachPresignedMediaToSlides(outDeck.slides || slides)
  );
  return withFlatPresentationFields({
    project,
    deck: { ...outDeck, slides: signedSlides },
    slides: signedSlides,
  });
}

async function listPresentationDeckPacks() {
  return deckPackGalleryService.listActiveDeckPacks();
}

async function getPresentationDeckPack(packId) {
  return deckPackGalleryService.getActiveDeckPack(packId);
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

  const proj = fullProject || project;
  const deckPayload = {
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
  };
  const slides = enrichSlidesForClient(await attachPresignedMediaToSlides(deck.slides || []));

  return withFlatPresentationFields({
    project: proj,
    deck: deckPayload,
    slides,
  });
}

async function getSlide({ workspaceId, presentationId, slideId }) {
  const { deck } = await deckGeneration.loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) {
    throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }
  const [signed] = enrichSlidesForClient(await attachPresignedMediaToSlides([slide]));
  return { slide: signed };
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
  title = null,
  generate = false,
  prompt = null,
  target = 'all',
}) {
  let slideContent = content && typeof content === 'object' ? { ...content } : {};
  if (title != null && String(title).trim() && !slideContent.title) {
    slideContent.title = String(title).trim();
  }

  const created = await slideEditor.addSlide({
    workspaceId,
    presentationId,
    afterSlideId,
    templateId,
    layoutId,
    content: slideContent,
  });

  if (!generate) {
    return created;
  }

  const promptText =
    (prompt != null && String(prompt).trim()) ||
    (slideContent.title && String(slideContent.title).trim()) ||
    null;

  const normalizedTarget = String(target || 'all').toLowerCase() === 'full' ? 'all' : target || 'all';

  const regen = await deckGeneration.regenerateSlide({
    workspaceId,
    presentationId,
    slideId: created.slide.id,
    userId,
    target: normalizedTarget,
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
  listPresentations,
  getPresentation,
  getSlide,
  creditEstimate,
  listPresentationDeckPacks,
  getPresentationDeckPack,
  applyBrandKit,
  generateOutline: deckGeneration.generateOutline,
  updateOutline: deckGeneration.updateOutline,
  setTheme: deckGeneration.setTheme,
  startGenerate: deckGeneration.startGenerate,
  getStatus: deckGeneration.getStatus,
  regenerateSlide: async (args) => {
    const target = String(args?.target || 'all').toLowerCase() === 'full' ? 'all' : args?.target || 'all';
    return deckGeneration.regenerateSlide({ ...args, target });
  },
  patchSlide: async (...args) =>
    presignPresentationPayload(await deckGeneration.patchSlide(...args)),
  queueExport: exportService.queueExport,
  getExport: exportService.getExport,
  listThemes: themeService.listThemes,
  ...slideEditor,
  addSlide,
  blankCanvas,
  uploadSlideMedia: async (...args) => {
    const slideMedia = require('./slideMedia.service');
    return slideMedia.uploadSlideMedia(...args);
  },
  attachSlideAsset: async (...args) => {
    const slideMedia = require('./slideMedia.service');
    return slideMedia.attachSlideAsset(...args);
  },
  insertSlideStock: async (...args) => {
    const slideMedia = require('./slideMedia.service');
    return slideMedia.insertSlideStock(...args);
  },
};
