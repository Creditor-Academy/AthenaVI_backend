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
  });

  return successResponse(req, res, data, 201, messages.PRESENTATION_CREATED);
});

const getPresentation = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await presentationService.getPresentation(workspaceId, presentationId);
  return successResponse(req, res, data, 200, messages.PRESENTATION_FETCHED);
});

const generateOutline = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const userId = req.user.id;
  const { source, prompt, outlineText, documentText, slideCount, density, locale } = req.body;

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
  const { density, overwriteManualEdits, requestHash } = req.body || {};

  const data = await presentationService.startGenerate({
    workspaceId,
    presentationId,
    userId,
    density,
    overwriteManualEdits,
    requestHash,
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
  const data = await presentationService.addElement({
    workspaceId,
    presentationId,
    slideId,
    presetId: req.body.presetId,
    element: req.body.element,
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
  const { contentType } = req.query || {};
  const data = await presentationService.listDeckLayouts({ contentType });
  return successResponse(req, res, { templates: data }, 200, messages.PRESENTATION_TEMPLATES_FETCHED);
});

const listPresentationThemes = asyncHandler(async (req, res) => {
  const data = presentationService.listThemes();
  return successResponse(req, res, { themes: data }, 200, messages.PRESENTATION_THEMES_FETCHED);
});

const listPresentationElements = asyncHandler(async (req, res) => {
  const data = presentationService.listElementCatalog();
  return successResponse(req, res, data, 200, messages.PRESENTATION_ELEMENTS_CATALOG);
});

module.exports = {
  createPresentation,
  getPresentation,
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
  deleteElement,
  reorderElements,
  regenerateSlide,
  queueExport,
  getExport,
  creditEstimate,
  listPresentationTemplates,
  listPresentationThemes,
  listPresentationElements,
};
