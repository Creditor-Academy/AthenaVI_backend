const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const presentationDao = require('../presentation/presentation.dao');
const s3Service = require('../s3/s3.service');
const brandKitDao = require('./brandKit.dao');
const brandKitCredit = require('./brandKitCredit.service');
const brandKitService = require('./brandKit.service');
const {
  CANVAS,
  DEFAULT_GUIDELINE_TEMPLATE_ID,
  buildGuidelineSlides,
  deckThemeTokensForTemplate,
  getGuidelineTemplate,
  listGuidelineTemplates,
} = require('./brandKit.guidelineTemplates');

async function resolveMediaUrl(media) {
  if (!media?.s3Key) return media?.url || null;
  try {
    return await s3Service.getPresignedGetUrl(media.s3Key, 3600);
  } catch {
    return media.url || s3Service.buildPublicUrl(media.s3Key);
  }
}

async function kitWithPresignedMedia(kit) {
  const media = await Promise.all(
    (kit.media || []).map(async (m) => ({
      ...m,
      url: await resolveMediaUrl(m),
    }))
  );
  return { ...kit, media };
}

function assertGuidelineReady(kit) {
  brandKitService.validateBrandKitData(kit.data);
  if (!String(kit.name || '').trim()) {
    throw new AppError('Brand kit name is required to generate guidelines', 400);
  }
}

/** Explicit request wins, then the kit's last-used template, then the default. */
function resolveTemplateId(requested, kit) {
  return getGuidelineTemplate(
    requested || kit.data?.meta?.guidelineTemplateId || DEFAULT_GUIDELINE_TEMPLATE_ID
  ).id;
}

async function generateGuideline({ workspaceId, userId, brandKitId, folderId, templateId }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const feature = brandKitCredit.BRAND_KIT_FEATURE.GUIDELINE_GENERATE;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  assertGuidelineReady(kit);
  const resolvedTemplateId = resolveTemplateId(templateId, kit);
  const kitReady = await kitWithPresignedMedia(kit);
  const themeTokens = deckThemeTokensForTemplate(
    brandKitService.brandKitToThemeTokens(kitReady),
    resolvedTemplateId
  );
  const slidePayloads = buildGuidelineSlides(kitReady, themeTokens, resolvedTemplateId);
  const deckName = `${kit.name} — Brand Guidelines`;
  const warnings = [];
  const hasPrimaryLogo = (kitReady.media || []).some(
    (m) => m.kind === 'logo' && (m.role === 'primary' || !m.role)
  );
  if (!hasPrimaryLogo) {
    warnings.push('primary_logo_missing');
  }

  const slideRows = slidePayloads.map((s) => ({
    order: s.order,
    contentType: s.contentType,
    layoutId: s.layoutId,
    content: s.content,
    imageRef: null,
    elements: s.elements,
    status: 'READY',
    manuallyEdited: true,
  }));

  const existingProjectId = kit.data?.meta?.guidelineProjectId || null;
  let project = null;
  let deck = null;
  let regenerated = false;

  if (existingProjectId) {
    const existingProject = await prisma.project.findFirst({
      where: { id: existingProjectId, workspaceId },
      select: { id: true, name: true, folderId: true },
    });
    const existingDeck = existingProject
      ? await presentationDao.findDeckByProjectId(existingProjectId)
      : null;

    if (existingProject && existingDeck) {
      await presentationDao.deleteSlidesByDeckId(existingDeck.id);
      await presentationDao.updateDeck(existingDeck.id, { themeTokens, status: 'DRAFT' });
      await presentationDao.updateProjectName(existingProjectId, deckName);
      await presentationDao.createSlides(existingDeck.id, slideRows);
      project = existingProject;
      deck = await presentationDao.findDeckById(existingDeck.id);
      regenerated = true;
    }
  }

  if (!project || !deck) {
    const folder = await prisma.folder.findFirst({
      where: { id: folderId, workspaceId },
      select: { id: true },
    });
    if (!folder) throw new AppError(messages.FOLDER_NOT_FOUND, 404);

    const created = await presentationDao.createPresentationProject({
      workspaceId,
      folderId,
      name: deckName,
      createdBy: userId,
      themeTokens,
      aspectRatio: '16:9',
      locale: 'en',
    });
    project = created.project;
    deck = created.deck;
    await presentationDao.createSlides(deck.id, slideRows);
  }

  const meta = (kit.data && kit.data.meta) || {};
  if (meta.guidelineProjectId !== project.id || meta.guidelineTemplateId !== resolvedTemplateId) {
    await brandKitDao.updateKit({
      workspaceId,
      brandKitId,
      data: {
        ...(kit.data && typeof kit.data === 'object' ? kit.data : {}),
        meta: { ...meta, guidelineProjectId: project.id, guidelineTemplateId: resolvedTemplateId },
      },
    });
  }

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: `brandKit:guideline:${workspaceId}:${brandKitId}:${Date.now()}`,
    metadata: { brandKitId, action: 'guideline_generate', projectId: project.id, templateId: resolvedTemplateId },
  });

  const refreshedDeck = await presentationDao.findDeckByProjectId(project.id);

  return {
    presentationId: project.id,
    deckId: deck.id,
    name: deckName,
    slideCount: slidePayloads.length,
    status: refreshedDeck?.status || 'DRAFT',
    templateId: resolvedTemplateId,
    themeTokens,
    warnings,
    regenerated,
  };
}

/**
 * Build the guideline slides for a template without saving or charging — lets users
 * compare templates before generating. Same builder as generateGuideline, so what they
 * see is what they get.
 */
async function previewGuideline({ workspaceId, brandKitId, templateId }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  assertGuidelineReady(kit);

  const resolvedTemplateId = resolveTemplateId(templateId, kit);
  const kitReady = await kitWithPresignedMedia(kit);
  const themeTokens = deckThemeTokensForTemplate(
    brandKitService.brandKitToThemeTokens(kitReady),
    resolvedTemplateId
  );
  const slides = buildGuidelineSlides(kitReady, themeTokens, resolvedTemplateId).map((s) => ({
    id: `preview_${resolvedTemplateId}_${s.order}`,
    order: s.order,
    contentType: s.contentType,
    layoutId: s.layoutId,
    content: s.content,
    elements: s.elements,
    status: 'READY',
  }));

  return { templateId: resolvedTemplateId, aspectRatio: '16:9', themeTokens, slides };
}

async function getGuidelineInfo(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const templateId = resolveTemplateId(null, kit);
  const templates = listGuidelineTemplates();
  const projectId = kit.data?.meta?.guidelineProjectId || null;
  if (!projectId) {
    return { linked: false, presentationId: null, status: null, slideCount: 0, templateId, templates };
  }

  const deck = await presentationDao.findDeckByProjectId(projectId);
  if (!deck) {
    return { linked: false, presentationId: projectId, status: 'missing', slideCount: 0, templateId, templates };
  }

  const project = await prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    select: { id: true, name: true },
  });

  return {
    linked: true,
    presentationId: projectId,
    name: project?.name || null,
    status: deck.status,
    slideCount: (deck.slides || []).length,
    aspectRatio: deck.aspectRatio,
    templateId,
    templates,
  };
}

module.exports = {
  buildGuidelineSlides,
  generateGuideline,
  getGuidelineInfo,
  previewGuideline,
  listGuidelineTemplates,
  CANVAS,
};
