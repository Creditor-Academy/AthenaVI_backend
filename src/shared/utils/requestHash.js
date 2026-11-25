const crypto = require('crypto');

const {
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  isAvatar6Engine,
  normalizeHeygenAvatarEngine,
} = require('../constants/heygen');

/**
 * `motionExpressiveness` only affects Avatar 6 and only when it is not the default, so it joins the
 * hash in that case alone. Every other request keeps exactly the hash it had before.
 */
function generateHeygenRequestHash({
  workspaceId,
  projectId,
  sceneId,
  avatarId,
  voiceId,
  script,
  avatarEngine,
  outputFormat = 'mp4',
  motionExpressiveness,
}) {
  if (!workspaceId || !projectId || !sceneId || !avatarId || !voiceId || !script) {
    throw new Error('Missing required fields for HeyGen request hash');
  }

  const normalizedScript = String(script).trim().toLowerCase();
  const engine = normalizeHeygenAvatarEngine(avatarEngine ?? DEFAULT_HEYGEN_AVATAR_ENGINE);
  const format = String(outputFormat || 'mp4').trim().toLowerCase() === 'webm' ? 'webm' : 'mp4';

  const hashInput = {
    workspaceId,
    projectId,
    sceneId: String(sceneId).trim(),
    avatarId,
    voiceId,
    script: normalizedScript,
    avatarEngine: engine,
    outputFormat: format,
  };
  if (
    isAvatar6Engine(engine) &&
    String(motionExpressiveness || '').trim().toLowerCase() === 'less'
  ) {
    hashInput.motionExpressiveness = 'less';
  }

  const payload = JSON.stringify(hashInput);

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
