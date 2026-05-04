const crypto = require('crypto');

const generateHeygenRequestHash = ({
  workspaceId,
  projectId,
  sceneId,
  avatarId,
  voiceId,
  script,
}) => {
  if (!workspaceId || !projectId || !sceneId || !avatarId || !voiceId || !script) {
    throw new Error('Missing required fields for HeyGen request hash');
  }

  const normalizedScript = String(script).trim().toLowerCase();

  const payload = JSON.stringify({
    workspaceId,
    projectId,
    sceneId: String(sceneId).trim(),
    avatarId,
    voiceId,
    script: normalizedScript,
  });

  return crypto.createHash('sha256').update(payload).digest('hex');
};

module.exports = {
  generateHeygenRequestHash,
};
