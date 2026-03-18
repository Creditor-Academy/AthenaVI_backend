const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const renderService = require('./render.service');

const startRender = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const job = await renderService.startRender(userId, workspaceId, videoId);
  return successResponse(req, res, { job }, 201);
});

const getRenderJob = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const jobId = req.params.jobId;
  const job = await renderService.getRenderJob(userId, workspaceId, jobId);
  return successResponse(req, res, { job }, 200, null);
});

module.exports = {
  startRender,
  getRenderJob,
};
