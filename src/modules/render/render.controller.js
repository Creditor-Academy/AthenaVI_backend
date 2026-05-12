const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const renderService = require('./render.service');

const createRender = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const render = await renderService.startProjectRender({
    workspaceId,
    projectId,
    userId: req.user.id,
    forceRebuild: Boolean(req.body.forceRebuild),
  });

  return successResponse(req, res, { render }, 202, messages.PROJECT_RENDER_STARTED);
});

const listRenders = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const renders = await renderService.listProjectRenders(workspaceId, projectId);

  return successResponse(req, res, { renders }, 200, messages.PROJECT_RENDERS_FETCHED);
});

const getRender = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, renderId } = req.params;
  const render = await renderService.getProjectRender(workspaceId, projectId, renderId);

  return successResponse(req, res, { render }, 200, messages.PROJECT_RENDER_FETCHED);
});

const getRenderDownloadUrl = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, renderId } = req.params;
  const download = await renderService.getRenderDownloadUrl(workspaceId, projectId, renderId);

  return successResponse(req, res, download, 200, messages.PROJECT_RENDER_DOWNLOAD_READY);
});

module.exports = {
  createRender,
  listRenders,
  getRender,
  getRenderDownloadUrl,
};
