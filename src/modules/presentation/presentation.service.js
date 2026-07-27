const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const themeService = require('./theme.service');
const deckGeneration = require('./deckGeneration.service');
const exportService = require('./export.service');

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
}) {
  const folder = await prisma.folder.findFirst({
    where: { id: folderId, workspaceId },
    select: { id: true, workspaceId: true },
  });
  if (!folder) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
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

  return { project, deck };
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

module.exports = {
  createPresentation,
  getPresentation,
  creditEstimate,
  // Generation
  generateOutline: deckGeneration.generateOutline,
  updateOutline: deckGeneration.updateOutline,
  setTheme: deckGeneration.setTheme,
  startGenerate: deckGeneration.startGenerate,
  getStatus: deckGeneration.getStatus,
  regenerateSlide: deckGeneration.regenerateSlide,
  patchSlide: deckGeneration.patchSlide,
  // Export
  queueExport: exportService.queueExport,
  getExport: exportService.getExport,
  listThemes: themeService.listThemes,
};
