const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const presentationService = require('./presentation.service');

const createPresentation = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const userId = req.user.id;
  const {
    title,
    name,
    folderId,
    themeId,
    themeTokens,
    locale,
    aspectRatio,
    createMode,
    templateId,
    packId,
    brandKitId,
  } = req.body;

  const data = await presentationService.createPresentation({
    workspaceId,
    userId,
    folderId,
    name,
    title,
    themeId,
    themeTokens,
    locale,
    aspectRatio,
    createMode,
    templateId,
    packId,
    brandKitId,
  });

  return successResponse(req, res, data, 201, messages.PRESENTATION_CREATED);
});

const listPresentations = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const { folderId } = req.query;
  const presentations = await presentationService.listPresentations({
    workspaceId,
    folderId,
  });
  return successResponse(
    req,
    res,
    { presentations },
    200,
    messages.PRESENTATIONS_FETCHED
  );
});

const getPresentation = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.getPresentation(workspaceId, presentationId);
  return successResponse(req, res, data, 200, messages.PRESENTATION_FETCHED);
});

const updateThumbnail = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.updateThumbnail(workspaceId, presentationId, {
    thumbnailUrl: req.body.thumbnailUrl,
    slideId: req.body.slideId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_THUMBNAIL_UPDATED);
});

const getSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.getSlide({ workspaceId, presentationId, slideId });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_FETCHED || messages.PRESENTATION_FETCHED);
});

const generateOutline = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const userId = req.user.id;
  const { source, prompt, outlineText, documentText, slideCount, density, locale, voiceAndTone, audience, purpose, imageType, imageStyle, imageStyleFilter, colorTheme, optionalOutline } = req.body;

  const data = await presentationService.generateOutline({
    workspaceId,
    presentationId,
    userId,
    source,
    prompt,
    outlineText,
    documentText,
    file: req.file,
    slideCount,
    density,
    locale,
    voiceAndTone,
    audience,
    purpose,
    imageType,
    imageStyle,
    imageStyleFilter,
    colorTheme,
    optionalOutline,
  });

  return successResponse(req, res, data, 200, messages.PRESENTATION_OUTLINE_GENERATED);
});

const updateOutline = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.updateOutline({
    workspaceId,
    presentationId,
    outline: req.body,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_OUTLINE_UPDATED);
});

const setTheme = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const { themeId, themeTokens } = req.body;
  const data = await presentationService.setTheme({
    workspaceId,
    presentationId,
    themeId,
    themeTokens,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_THEME_UPDATED);
});

const startGenerate = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const userId = req.user.id;
  const { density, overwriteManualEdits, requestHash, generationFlow } = req.body || {};

  const data = await presentationService.startGenerate({
    workspaceId,
    presentationId,
    userId,
    density,
    overwriteManualEdits,
    requestHash,
    generationFlow,
  });

  return successResponse(req, res, data, 202, messages.PRESENTATION_GENERATION_STARTED);
});

const getStatus = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.getStatus(presentationId, workspaceId);
  return successResponse(req, res, data, 200, messages.PRESENTATION_STATUS_FETCHED);
});

const patchSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.patchSlide({
    workspaceId,
    presentationId,
    slideId,
    patch: req.body,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_UPDATED);
});

const addSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.addSlide({
    workspaceId,
    presentationId,
    userId: req.user.id,
    ...(req.body || {}),
  });
  return successResponse(req, res, data, 201, messages.PRESENTATION_SLIDE_CREATED);
});

const deleteSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.deleteSlide({
    workspaceId,
    presentationId,
    slideId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_DELETED);
});

const duplicateSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.duplicateSlide({
    workspaceId,
    presentationId,
    slideId,
  });
  return successResponse(req, res, data, 201, messages.PRESENTATION_SLIDE_DUPLICATED);
});

const reorderSlides = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.reorderSlides({
    workspaceId,
    presentationId,
    slideIds: req.body.slideIds,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDES_REORDERED);
});

const applyLayout = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.applyLayout({
    workspaceId,
    presentationId,
    slideId,
    templateId: req.body.templateId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_LAYOUT_APPLIED);
});

const putCanvas = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.putCanvas({
    workspaceId,
    presentationId,
    slideId,
    canvas: req.body,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_CANVAS_UPDATED);
});

const addElement = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const body = req.body || {};
  const data = await presentationService.addElement({
    workspaceId,
    presentationId,
    slideId,
    presetId: body.presetId,
    element: body.element,
    type: body.type,
    placement: body.placement,
    content: body.content,
    role: body.role,
    layer: body.layer,
  });
  return successResponse(req, res, data, 201, messages.PRESENTATION_ELEMENT_CREATED);
});

const patchElement = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId, elementId } = req.params;
  const data = await presentationService.patchElement({
    workspaceId,
    presentationId,
    slideId,
    elementId,
    patch: req.body,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENT_UPDATED);
});

const patchElementsBatch = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.patchElementsBatch({
    workspaceId,
    presentationId,
    slideId,
    patches: req.body.patches,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_BATCH_UPDATED);
});

const groupElements = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.groupElements({
    workspaceId,
    presentationId,
    slideId,
    elementIds: req.body.elementIds,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_GROUPED);
});

const ungroupElements = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.ungroupElements({
    workspaceId,
    presentationId,
    slideId,
    elementId: req.body.elementId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_UNGROUPED);
});

const alignElements = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.alignElements({
    workspaceId,
    presentationId,
    slideId,
    elementIds: req.body.elementIds,
    alignment: req.body.alignment,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_ALIGNED);
});

const deleteElement = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId, elementId } = req.params;
  const data = await presentationService.deleteElement({
    workspaceId,
    presentationId,
    slideId,
    elementId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENT_DELETED);
});

const reorderElements = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const data = await presentationService.reorderElements({
    workspaceId,
    presentationId,
    slideId,
    elementIds: req.body.elementIds,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_REORDERED);
});

const regenerateSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const userId = req.user.id;
  const { target, overwriteManualEdits, prompt } = req.body || {};

  const data = await presentationService.regenerateSlide({
    workspaceId,
    presentationId,
    slideId,
    userId,
    target,
    overwriteManualEdits,
    prompt,
  });

  return successResponse(req, res, data, 202, messages.PRESENTATION_SLIDE_REGENERATE_STARTED);
});

const queueExport = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const userId = req.user.id;
  const { format, slideId } = req.body;

  const data = await presentationService.queueExport({
    workspaceId,
    presentationId,
    userId,
    format,
    slideId,
  });

  return successResponse(req, res, data, 202, messages.PRESENTATION_EXPORT_QUEUED);
});

const getExport = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, exportId } = req.params;
  const data = await presentationService.getExport({
    workspaceId,
    presentationId,
    exportId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_EXPORT_FETCHED);
});

const creditEstimate = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const { slideCount } = req.query || {};
  const data = await presentationService.creditEstimate({
    workspaceId,
    presentationId,
    slideCount,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_CREDIT_ESTIMATE);
});

const listPresentationTemplates = asyncHandler(async (req, res) => {
  const { contentType, category } = req.query || {};
  const data = await presentationService.listDeckLayouts({ contentType, category });
  return successResponse(
    req,
    res,
    { categories: data.categories, templates: data.templates },
    200,
    messages.PRESENTATION_TEMPLATES_FETCHED
  );
});

const listPresentationThemes = asyncHandler(async (req, res) => {
  const data = presentationService.listThemes();
  return successResponse(req, res, { themes: data }, 200, messages.PRESENTATION_THEMES_FETCHED);
});

const listPresentationElements = asyncHandler(async (req, res) => {
  const data = presentationService.listElementCatalog();
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_CATALOG);
});

const listPresentationDeckPacks = asyncHandler(async (req, res) => {
  const data = await presentationService.listPresentationDeckPacks();
  return successResponse(req, res, { packs: data }, 200, messages.PRESENTATION_DECK_PACKS_FETCHED);
});

const getPresentationDeckPack = asyncHandler(async (req, res) => {
  const pack = await presentationService.getPresentationDeckPack(req.params.packId);
  return successResponse(req, res, { pack }, 200, messages.PRESENTATION_DECK_PACK_FETCHED);
});

const applyBrandKit = asyncHandler(async (req, res) => {
  const data = await presentationService.applyBrandKit({
    workspaceId: req.params.workspaceId,
    presentationId: req.params.presentationId,
    brandKitId: req.body.brandKitId,
    userId: req.user?.id,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_BRAND_KIT_APPLIED);
});

const uploadSlideMedia = asyncHandler(async (req, res) => {
  const data = await presentationService.uploadSlideMedia({
    workspaceId: req.params.workspaceId,
    presentationId: req.params.presentationId,
    slideId: req.params.slideId,
    file: req.file,
    elementId: req.body?.elementId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_MEDIA_UPLOADED);
});

const attachSlideAsset = asyncHandler(async (req, res) => {
  const data = await presentationService.attachSlideAsset({
    workspaceId: req.params.workspaceId,
    presentationId: req.params.presentationId,
    slideId: req.params.slideId,
    assetId: req.body.assetId,
    elementId: req.body.elementId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_ASSET_ATTACHED);
});

const insertSlideStock = asyncHandler(async (req, res) => {
  const data = await presentationService.insertSlideStock({
    workspaceId: req.params.workspaceId,
    presentationId: req.params.presentationId,
    slideId: req.params.slideId,
    query: req.body.query,
    provider: req.body.provider,
    externalId: req.body.externalId,
    elementId: req.body.elementId,
    userId: req.user.id,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SLIDE_STOCK_INSERTED);
});

module.exports = {
  createPresentation,
  listPresentations,
  getPresentation,
  updateThumbnail,
  getSlide,
  generateOutline,
  updateOutline,
  setTheme,
  startGenerate,
  getStatus,
  patchSlide,
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
  regenerateSlide,
  queueExport,
  getExport,
  creditEstimate,
  listPresentationTemplates,
  listPresentationThemes,
  listPresentationElements,
  listPresentationDeckPacks,
  getPresentationDeckPack,
  applyBrandKit,
  uploadSlideMedia,
  attachSlideAsset,
  insertSlideStock,
};
