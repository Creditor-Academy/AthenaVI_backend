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

const regenerateSlide = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, slideId } = req.params;
  const userId = req.user.id;
  const { target, overwriteManualEdits } = req.body || {};

  const data = await presentationService.regenerateSlide({
    workspaceId,
    presentationId,
    slideId,
    userId,
    target,
    overwriteManualEdits,
  });

  return successResponse(req, res, data, 202, messages.PRESENTATION_SLIDE_REGENERATE_STARTED);
});

const queueExport = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const userId = req.user.id;
  const { format } = req.body;

  const data = await presentationService.queueExport({
    workspaceId,
    presentationId,
    userId,
    format,
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

module.exports = {
  createPresentation,
  getPresentation,
  generateOutline,
  updateOutline,
  setTheme,
  startGenerate,
  getStatus,
  patchSlide,
  regenerateSlide,
  queueExport,
  getExport,
  creditEstimate,
};
