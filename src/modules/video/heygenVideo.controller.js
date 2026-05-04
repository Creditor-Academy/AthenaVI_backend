const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const heygenService = require('./services/heygen.service');

const createHeygenVideo = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const row = await heygenService.generateAvatarVideo({
    workspaceId,
    projectId,
    ...req.body,
  });
  return successResponse(req, res, { heygenVideo: row }, 201, messages.VIDEO_GENERATION_SUCCESS);
});

const listHeygenVideos = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const rows = await heygenService.listProjectHeygenVideos(workspaceId, projectId);
  return successResponse(req, res, { heygenVideos: rows }, 200, messages.HEYGEN_VIDEOS_FETCHED);
});

const getHeygenVideo = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, heygenVideoId } = req.params;
  const row = await heygenService.getProjectHeygenVideo(workspaceId, projectId, heygenVideoId, {
    sync: true,
  });
  return successResponse(req, res, { heygenVideo: row }, 200, messages.HEYGEN_VIDEO_FETCHED);
});

const downloadHeygenVideo = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, heygenVideoId } = req.params;
  const expiresIn = req.query.expiresIn;
  const result = await heygenService.getPresignedDownloadForVideo(
    workspaceId,
    projectId,
    heygenVideoId,
    expiresIn
  );
  return successResponse(
    req,
    res,
    {
      presignedUrl: result.presignedUrl,
      expiresInSeconds: result.expiresInSeconds,
      heygenVideo: result.heygenResponse,
    },
    200,
    messages.HEYGEN_VIDEO_FETCHED
  );
});

module.exports = {
  createHeygenVideo,
  listHeygenVideos,
  getHeygenVideo,
  downloadHeygenVideo,
};
