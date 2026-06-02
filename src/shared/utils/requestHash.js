const crypto = require('crypto');

const {
  DEFAULT_HEYGEN_AVATAR_ENGINE,
  normalizeHeygenAvatarEngine,
} = require('../constants/heygen');

const generateHeygenRequestHash = ({
  workspaceId,
  projectId,
  sceneId,
  avatarId,
  voiceId,
  script,
  avatarEngine,
}) => {
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
};

module.exports = {
  generateHeygenRequestHash,
};
