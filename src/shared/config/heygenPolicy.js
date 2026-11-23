'use strict';

const AppError = require('../utils/AppError');
const messages = require('../utils/messages');

function envFlagTrue(name) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return false;
  const normalized = String(raw).trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

/**
 * Digital twin avatar creation (HeyGen training + consent flow).
 * Default **off** — set `HEYGEN_DIGITAL_TWIN_CREATE_ENABLED=true` when the API key has twin access.
 */
function isHeygenDigitalTwinCreateEnabled() {
  return envFlagTrue('HEYGEN_DIGITAL_TWIN_CREATE_ENABLED');
}

/**
 * @param {'digital_twin'|'photo'|'prompt'|string} avatarCreateType
 */
function assertHeygenAvatarCreateTypeAllowed(avatarCreateType) {
  const type = avatarCreateType != null ? String(avatarCreateType).trim().toLowerCase() : '';
  if (type === 'digital_twin' && !isHeygenDigitalTwinCreateEnabled()) {
    throw new AppError(messages.HEYGEN_DIGITAL_TWIN_CREATE_DISABLED, 403);
  }
}

/** Training video uploads are only used for digital twin creation when policy is off. */
function assertHeygenAvatarTrainingUploadAllowed(mimeType) {
  const mime = mimeType != null ? String(mimeType).trim().toLowerCase() : '';
  if (!isHeygenDigitalTwinCreateEnabled() && (mime === 'video/mp4' || mime === 'video/webm')) {
    throw new AppError(messages.HEYGEN_DIGITAL_TWIN_CREATE_DISABLED, 403);
  }
}

module.exports = {
  isHeygenDigitalTwinCreateEnabled,
  assertHeygenAvatarCreateTypeAllowed,
  assertHeygenAvatarTrainingUploadAllowed,
};