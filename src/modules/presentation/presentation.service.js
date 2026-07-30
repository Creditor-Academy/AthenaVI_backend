const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const themeService = require('./theme.service');
const deckGeneration = require('./deckGeneration.service');
const exportService = require('./export.service');
const slideEditor = require('./slideEditor.service');
const { layoutSlotsToElements, blankCanvas } = require('./layoutToElements');

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
}) {
  const folder = await prisma.folder.findFirst({
    where: { id: folderId, workspaceId },
    select: { id: true, workspaceId: true },
  });
  if (!folder) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }

  const mode = createMode === 'template' ? 'template' : 'blank';
  if (mode === 'template' && !templateId) {
    throw new AppError('templateId is required when createMode is template', 400);
  }

  let template = null;
  if (mode === 'template') {
    template = await presentationDao.findTemplateById(templateId);
    if (!template || template.type !== 'DECK_LAYOUT' || !template.isActive) {
      throw new AppError(messages.PRESENTATION_TEMPLATE_NOT_FOUND, 404);
    }
  }

  const resolvedTokens = themeService.resolveThemeTokens({ themeId, themeTokens });
  const displayName = String(name || title || 'Untitled presentation').trim();

  const { project, deck } = await presentationDao.createPresentationProject({
    workspaceId,
    folderId,
    name: displayName,
    createdBy: userId,
    themeTokens: resolvedTokens,
    aspectRatio,
    locale,
  });

  let slides = deck.slides || [];
  if (mode === 'template' && template) {
    const elementsDoc = layoutSlotsToElements(template.schema, { title: displayName }, null);
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

  const refreshed = await presentationDao.findDeckById(deck.id);
  return { project, deck: refreshed || { ...deck, slides } };
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
    slides: deck.slides || [],
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
  generateOutline: deckGeneration.generateOutline,
  updateOutline: deckGeneration.updateOutline,
  setTheme: deckGeneration.setTheme,
  startGenerate: deckGeneration.startGenerate,
  getStatus: deckGeneration.getStatus,
  regenerateSlide: deckGeneration.regenerateSlide,
  patchSlide: deckGeneration.patchSlide,
  queueExport: exportService.queueExport,
  getExport: exportService.getExport,
  listThemes: themeService.listThemes,
  ...slideEditor,
  addSlide,
  blankCanvas,
};
