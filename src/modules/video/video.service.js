const videoDao = require('./video.dao');
const workspaceDao = require('../workspace/workspace.dao');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { estimateDuration } = require('../../shared/utils/ttsDuration');

async function ensureWorkspaceAccess(userId, workspaceId) {
  const membership = await workspaceDao.findWorkspaceMember(workspaceId, userId);
  if (!membership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  return membership;
}

async function ensureVideoInWorkspace(videoId, workspaceId) {
  const video = await videoDao.findVideoById(videoId);
  if (!video) throw new AppError(messages.VIDEO_NOT_FOUND, 404);
  if (video.workspaceId !== workspaceId) throw new AppError(messages.VIDEO_FORBIDDEN, 403);
  return video;
}

async function ensureSceneInVideo(sceneId, videoId) {
  const scene = await videoDao.findSceneById(sceneId);
  if (!scene) throw new AppError(messages.SCENE_NOT_FOUND, 404);
  if (scene.videoId !== videoId) throw new AppError(messages.SCENE_FORBIDDEN, 403);
  return scene;
}

async function createVideo(userId, workspaceId, body) {
  await ensureWorkspaceAccess(userId, workspaceId);

  const { name, aspectRatio, title, description } = body;
  const metadata = {};
  if (aspectRatio != null) metadata.aspectRatio = aspectRatio;
  if (title != null) metadata.title = title;
  if (description != null) metadata.description = description;

  return await videoDao.createVideo({
    workspaceId,
    name: name?.trim() || 'Untitled video',
    metadata: Object.keys(metadata).length ? metadata : undefined,
  });
}

async function getVideos(userId, workspaceId, options = {}) {
  await ensureWorkspaceAccess(userId, workspaceId);
  return await videoDao.findVideosByWorkspaceId(workspaceId, options);
}

async function getVideoById(userId, workspaceId, videoId, options = {}) {
  await ensureWorkspaceAccess(userId, workspaceId);
  const video = await ensureVideoInWorkspace(videoId, workspaceId);
  const { includeScenes = false } = options;
  if (includeScenes) {
    const scenes = await videoDao.findScenesByVideoId(videoId);
    return { ...video, scenes };
  }
  return video;
}

async function updateVideo(userId, workspaceId, videoId, body) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);

  const data = {};
  if (body.name != null) data.name = body.name.trim();
  if (body.aspectRatio != null || body.title != null || body.description != null) {
    const video = await videoDao.findVideoById(videoId);
    const metadata = (video.metadata && typeof video.metadata === 'object') ? { ...video.metadata } : {};
    if (body.aspectRatio != null) metadata.aspectRatio = body.aspectRatio;
    if (body.title != null) metadata.title = body.title;
    if (body.description != null) metadata.description = body.description;
    data.metadata = metadata;
  }
  if (Object.keys(data).length === 0) {
    return await videoDao.findVideoById(videoId);
  }
  return await videoDao.updateVideo(videoId, data);
}

async function deleteVideo(userId, workspaceId, videoId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  const video = await ensureVideoInWorkspace(videoId, workspaceId);
  await videoDao.deleteVideo(videoId);
  return video;
}

/**
 * TTS-driven timeline: set each scene's duration from script (estimate) and startTime (cumulative).
 * Returns video with updated scenes.
 */
async function alignTimeline(userId, workspaceId, videoId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  const video = await ensureVideoInWorkspace(videoId, workspaceId);
  const scenes = await videoDao.findScenesByVideoId(videoId);
  if (scenes.length === 0) {
    return { ...video, scenes: [] };
  }

  let cumulativeStart = 0;
  for (const scene of scenes) {
    const payload = scene.payload && typeof scene.payload === 'object' ? scene.payload : {};
    const scriptText = payload.scriptText != null ? String(payload.scriptText) : '';
    const duration = estimateDuration(scriptText);

    await videoDao.updateScene(scene.id, {
      duration,
      startTime: cumulativeStart,
    });
    cumulativeStart += duration;
  }

  const updatedScenes = await videoDao.findScenesByVideoId(videoId);
  return { ...video, scenes: updatedScenes };
}

/* =========================
   SCENES
========================= */

async function createScene(userId, workspaceId, videoId, body) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);

  const { order, startTime, duration, payload } = body;
  return await videoDao.createScene({
    videoId,
    order: typeof order === 'number' ? order : 0,
    startTime: typeof startTime === 'number' ? startTime : 0,
    duration: typeof duration === 'number' ? duration : 0,
    payload: payload && typeof payload === 'object' ? payload : {},
  });
}

async function getScenes(userId, workspaceId, videoId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);
  return await videoDao.findScenesByVideoId(videoId);
}

async function getSceneById(userId, workspaceId, videoId, sceneId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);
  return await ensureSceneInVideo(sceneId, videoId);
}

async function updateScene(userId, workspaceId, videoId, sceneId, body) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);
  await ensureSceneInVideo(sceneId, videoId);

  const data = {};
  if (body.order !== undefined) data.order = body.order;
  if (body.startTime !== undefined) data.startTime = body.startTime;
  if (body.duration !== undefined) data.duration = body.duration;
  if (body.payload !== undefined && typeof body.payload === 'object') data.payload = body.payload;

  if (Object.keys(data).length === 0) {
    return await videoDao.findSceneById(sceneId);
  }
  return await videoDao.updateScene(sceneId, data);
}

async function deleteScene(userId, workspaceId, videoId, sceneId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);
  const scene = await ensureSceneInVideo(sceneId, videoId);
  await videoDao.deleteScene(sceneId);
  return scene;
}

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
