function sanitizePathSegment(seg) {
  return String(seg || '')
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 180);
}

function buildProjectBasePrefix({ workspaceId, folderId, projectId }) {
  return [
    'workspaces',
    sanitizePathSegment(workspaceId),
    'folders',
    sanitizePathSegment(folderId),
    'projects',
    sanitizePathSegment(projectId),
  ].join('/');
}

function buildProjectRenderFinalKey({ workspaceId, folderId, projectId, renderId }) {
  return `${buildProjectBasePrefix({ workspaceId, folderId, projectId })}/renders/${sanitizePathSegment(renderId)}/final.mp4`;
}

function buildProjectSceneCacheKey({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  sceneHash,
}) {
  return `${buildProjectBasePrefix({ workspaceId, folderId, projectId })}/scene-cache/${sanitizePathSegment(sceneId)}/${sanitizePathSegment(sceneHash)}.mp4`;
}

function buildHeygenSceneVideoKey({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  heygenVideoId,
  outputFormat = 'mp4',
}) {
  const extension = String(outputFormat).toLowerCase() === 'webm' ? 'webm' : 'mp4';
  return `${buildProjectBasePrefix({ workspaceId, folderId, projectId })}/scenes/${sanitizePathSegment(sceneId)}/heygen/${sanitizePathSegment(heygenVideoId)}.${extension}`;
}

function buildSpeechSceneAudioKey({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  speechId,
}) {
  return `${buildProjectBasePrefix({ workspaceId, folderId, projectId })}/scenes/${sanitizePathSegment(sceneId)}/speech/${sanitizePathSegment(speechId)}.mp3`;
}

module.exports = {
  sanitizePathSegment,
  buildProjectBasePrefix,
  buildProjectRenderFinalKey,
  buildProjectSceneCacheKey,
  buildHeygenSceneVideoKey,
  buildSpeechSceneAudioKey,
};
