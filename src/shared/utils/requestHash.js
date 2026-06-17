const crypto = require('crypto');

const {
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  normalizeHeygenAvatarEngine,
} = require('../constants/heygen');

function generateHeygenRequestHash({
  workspaceId,
  projectId,
  sceneId,
  avatarId,
  voiceId,
  script,
  avatarEngine,
}) {
  if (!workspaceId || !projectId || !sceneId || !avatarId || !voiceId || !script) {
    throw new Error('Missing required fields for HeyGen request hash');
  }

  const normalizedScript = String(script).trim().toLowerCase();
  const engine = normalizeHeygenAvatarEngine(avatarEngine ?? DEFAULT_HEYGEN_AVATAR_ENGINE);

  const payload = JSON.stringify({
    workspaceId,
    projectId,
    sceneId: String(sceneId).trim(),
    avatarId,
    voiceId,
    script: normalizedScript,
    avatarEngine: engine,
  });

  return crypto.createHash('sha256').update(payload).digest('hex');
}

function generateSpeechRequestHash({
  workspaceId,
  projectId,
  sceneId,
  voiceId,
  script,
  speed = 1,
  inputType = 'text',
  locale = null,
}) {
  if (!workspaceId || !projectId || !sceneId || !voiceId || !script) {
    throw new Error('Missing required fields for speech request hash');
  }

  const normalizedScript = String(script).trim().toLowerCase();
  const normalizedLocale =
    locale != null && String(locale).trim() !== '' ? String(locale).trim().toLowerCase() : null;

  const payload = JSON.stringify({
    workspaceId,
    projectId,
    sceneId: String(sceneId).trim(),
    voiceId,
    script: normalizedScript,
    speed: Number(speed) || 1,
    inputType: String(inputType || 'text').trim().toLowerCase(),
    locale: normalizedLocale,
  });

  return crypto.createHash('sha256').update(payload).digest('hex');
}

module.exports = {
  generateHeygenRequestHash,
  generateSpeechRequestHash,
};
