const renderDao = require('./render.dao');
const videoDao = require('../video/video.dao');
const workspaceDao = require('../workspace/workspace.dao');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { renderQueue } = require('../../shared/config/renderQueue');

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

/**
 * Build inputProps for Remotion: { scenes, aspectRatio }.
 * Scenes are ordered and have id, order, startTime, duration, payload.
 */
function buildInputProps(video, scenes) {
  const metadata = video.metadata && typeof video.metadata === 'object' ? video.metadata : {};
  const aspectRatio = metadata.aspectRatio || '16:9';
  return {
    scenes: scenes.map((s) => ({
      id: s.id,
      order: s.order,
      startTime: s.startTime,
      duration: s.duration,
      payload: s.payload && typeof s.payload === 'object' ? s.payload : {},
    })),
    aspectRatio,
  };
}

async function startRender(userId, workspaceId, videoId) {
  await ensureWorkspaceAccess(userId, workspaceId);
  await ensureVideoInWorkspace(videoId, workspaceId);

  const job = await renderDao.createRenderJob({
    videoId,
    workspaceId,
    userId,
    status: 'PENDING',
  });

  await renderQueue.add(
    { jobId: job.id, videoId, workspaceId },
    { jobId: job.id }
  );

  return job;
}

async function getRenderJob(userId, workspaceId, jobId) {
  await ensureWorkspaceAccess(userId, workspaceId);

  const job = await renderDao.findRenderJobById(jobId);
  if (!job) throw new AppError(messages.RENDER_JOB_NOT_FOUND, 404);
  if (job.workspaceId !== workspaceId) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);

  return job;
}

module.exports = {
  startRender,
  getRenderJob,
  buildInputProps,
};
