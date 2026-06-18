const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const renderService = require('./render.service');
const s3Service = require('../s3/s3.service');

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

/** Authenticated pipe-through download (Bearer). Sets Content-Disposition so browsers save the file. */
const streamRender = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, renderId } = req.params;
  const render = await renderService.assertRenderDownloadable(workspaceId, projectId, renderId);
  const filename = await renderService.resolveRenderDownloadFilename(workspaceId, projectId);
  await s3Service.streamObjectToResponse(req, res, render.s3Key, {
    contentDisposition: `attachment; filename="${filename}"`,
  });
});

const headRenderStream = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, renderId } = req.params;
  const render = await renderService.assertRenderDownloadable(workspaceId, projectId, renderId);
  const meta = await s3Service.headObjectMeta(render.s3Key);
  const filename = await renderService.resolveRenderDownloadFilename(workspaceId, projectId);
  res.setHeader('Content-Type', meta.contentType || 'video/mp4');
  if (meta.contentLength != null) {
    res.setHeader('Content-Length', String(meta.contentLength));
  }
  if (meta.etag) {
    res.setHeader('ETag', meta.etag);
  }
  res.setHeader('Accept-Ranges', meta.acceptRanges);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'private, no-cache');
  return res.status(200).end();
});

const listWorkspaceVideos = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const videos = await renderService.listWorkspaceVideos(workspaceId, req.query);
  return successResponse(req, res, { videos }, 200, messages.PROJECT_RENDERS_FETCHED);
});

const listOwnerVideos = asyncHandler(async (req, res) => {
  const videos = await renderService.listOwnerVideos(req.user.id, req.query);
  return successResponse(req, res, { videos }, 200, messages.PROJECT_RENDERS_FETCHED);
});

module.exports = {
  createRender,
  listRenders,
  getRender,
  getRenderDownloadUrl,
  streamRender,
  headRenderStream,
  listWorkspaceVideos,
  listOwnerVideos,
};
