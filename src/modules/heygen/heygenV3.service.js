const { getJson, postJson, postForm } = require('../../shared/services/heygenV3.client');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

async function listAvatarGroups(query) {
  return getJson('/v3/avatars', query);
}

async function listAvatarLooks(query) {
  return getJson('/v3/avatars/looks', query);
}

async function createAvatar(body) {
  return postJson('/v3/avatars', body);
}

async function createAvatarConsent(groupId, body) {
  return postJson(`/v3/avatars/${encodeURIComponent(groupId)}/consent`, body || {});
}

async function listVoices(query) {
  return getJson('/v3/voices', query);
}

async function designVoice(body) {
  return postJson('/v3/voices', body);
}

async function cloneVoice(body) {
  return postJson('/v3/voices/clone', body);
}

async function getVoice(voiceId) {
  return getJson(`/v3/voices/${encodeURIComponent(voiceId)}`);
}

async function generateSpeechPreview(body) {
  return postJson('/v3/voices/speech', body);
}

async function uploadAsset(formData) {
  return postForm('/v3/assets', formData);
}

/** Normalize POST /v3/videos response */
function normalizeCreateVideoResponse(body) {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : body;
  const videoId =
    (data && typeof data === 'object' && (data.video_id ?? data.id)) ?? body?.video_id;
  if (!videoId) {
    throw new AppError(messages.HEYGEN_REQUEST_FAILED, 502);
  }
  const status =
    (data && typeof data === 'object' && data.status) || body?.status || 'processing';
  return { videoId: String(videoId), status: String(status), raw: body };
}

/** Normalize GET /v3/videos/:id response */
function normalizeVideoStatusResponse(body) {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : body;
  const id = (data && typeof data === 'object' && (data.id ?? data.video_id)) ?? body?.video_id;
  const statusRaw =
    (data && typeof data === 'object' && data.status) || body?.status || 'pending';
  const status = String(statusRaw).toLowerCase();
  return {
    id: id ? String(id) : null,
    status,
    video_url:
      data && typeof data === 'object' ? data.video_url ?? null : null,
    thumbnail_url:
      data && typeof data === 'object' ? data.thumbnail_url ?? null : null,
    duration: data && typeof data === 'object' ? data.duration ?? null : null,
    error:
      (data && typeof data === 'object' && data.error) || body?.error || null,
    raw: body,
  };
}

async function createVideo(jsonBody) {
  const raw = await postJson('/v3/videos', jsonBody);
  return { ...normalizeCreateVideoResponse(raw), raw };
}

async function getVideoStatus(videoId) {
  const raw = await getJson(`/v3/videos/${encodeURIComponent(videoId)}`);
  return normalizeVideoStatusResponse(raw);
}

module.exports = {
  listAvatarGroups,
  listAvatarLooks,
  createAvatar,
  createAvatarConsent,
  listVoices,
  designVoice,
  cloneVoice,
  getVoice,
  generateSpeechPreview,
  uploadAsset,
  createVideo,
  getVideoStatus,
};
