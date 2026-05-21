const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const heygenService = require('./services/heygen.service');
const s3Service = require('../s3/s3.service');

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

const getHeygenVideoS3Location = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, heygenVideoId } = req.params;
  const result = await heygenService.getS3ObjectLocationForVideo(
    workspaceId,
    projectId,
    heygenVideoId
  );
  return successResponse(
    req,
    res,
    {
      bucket: result.bucket,
      key: result.key,
      region: result.region,
      objectArn: result.objectArn,
      heygenVideo: result.heygenVideo,
    },
    200,
    messages.HEYGEN_VIDEO_S3_LOCATION
  );
});

/** Stable preview URL: pipe S3 bytes through API (Bearer auth). Supports Range for seeking. */
const streamHeygenVideo = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, heygenVideoId } = req.params;
  const row = await heygenService.assertHeygenVideoReadyInS3(
    workspaceId,
    projectId,
    heygenVideoId
  );
  await s3Service.streamObjectToResponse(req, res, row.s3Key);
});

const headHeygenVideoStream = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, heygenVideoId } = req.params;
  const row = await heygenService.assertHeygenVideoReadyInS3(
    workspaceId,
    projectId,
    heygenVideoId
  );
  const meta = await s3Service.headObjectMeta(row.s3Key);
  res.setHeader('Content-Type', meta.contentType);
  if (meta.contentLength != null) {
    res.setHeader('Content-Length', String(meta.contentLength));
  }
  if (meta.etag) {
    res.setHeader('ETag', meta.etag);
  }
  res.setHeader('Accept-Ranges', meta.acceptRanges);
  res.setHeader('Cache-Control', 'private, no-cache');
  return res.status(200).end();
});

module.exports = {
  createHeygenVideo,
  listHeygenVideos,
  getHeygenVideo,
  downloadHeygenVideo,
  getHeygenVideoS3Location,
  streamHeygenVideo,
  headHeygenVideoStream,
};
