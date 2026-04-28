const { getJson, postJson, postForm } = require('../../shared/services/heygenV3.client');

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

async function generateSpeechPreview(body) {
  return postJson('/v3/voices/speech', body);
}

async function uploadAsset(formData) {
  return postForm('/v3/assets', formData);
}

module.exports = {
  listAvatarGroups,
  listAvatarLooks,
  createAvatar,
  createAvatarConsent,
  listVoices,
  generateSpeechPreview,
  uploadAsset,
};
