const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const videoService = require('./video.service');

const createVideo = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const video = await videoService.createVideo(userId, workspaceId, req.body);
  return successResponse(req, res, { video }, 201);
});

const getVideos = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const includeScenes = req.query.include === 'scenes';
  const videos = await videoService.getVideos(userId, workspaceId, { includeScenes });
  return successResponse(req, res, { videos, count: videos.length }, 200, null);
});

const getVideoById = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const includeScenes = req.query.include === 'scenes';
  const video = await videoService.getVideoById(userId, workspaceId, videoId, { includeScenes });
  return successResponse(req, res, { video }, 200, null);
});

const updateVideo = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const video = await videoService.updateVideo(userId, workspaceId, videoId, req.body);
  return successResponse(req, res, { video }, 200, null);
});

const deleteVideo = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  await videoService.deleteVideo(userId, workspaceId, videoId);
  return successResponse(req, res, null, 200);
});

const alignTimeline = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const video = await videoService.alignTimeline(userId, workspaceId, videoId);
  return successResponse(req, res, { video }, 200, null);
});

const createScene = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const scene = await videoService.createScene(userId, workspaceId, videoId, req.body);
  return successResponse(req, res, { scene }, 201);
});

const getScenes = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const scenes = await videoService.getScenes(userId, workspaceId, videoId);
  return successResponse(req, res, { scenes, count: scenes.length }, 200, null);
});

const getSceneById = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const sceneId = req.params.sceneId;
  const scene = await videoService.getSceneById(userId, workspaceId, videoId, sceneId);
  return successResponse(req, res, { scene }, 200, null);
});

const updateScene = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const sceneId = req.params.sceneId;
  const scene = await videoService.updateScene(userId, workspaceId, videoId, sceneId, req.body);
  return successResponse(req, res, { scene }, 200, null);
});

const deleteScene = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const videoId = req.params.videoId;
  const sceneId = req.params.sceneId;
  await videoService.deleteScene(userId, workspaceId, videoId, sceneId);
  return successResponse(req, res, null, 200);
});

module.exports = {
  createVideo,
  getVideos,
  getVideoById,
  updateVideo,
  deleteVideo,
  alignTimeline,
  createScene,
  getScenes,
  getSceneById,
  updateScene,
  deleteScene,
};
