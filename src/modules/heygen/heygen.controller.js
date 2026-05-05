const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const heygenV3Service = require('./heygenV3.service');
const { createAvatarBodySchema } = require('./heygen.validation');

function assertCreateAvatarPayload(body) {
  if (body.type === 'prompt') {
    if (!body.prompt || !String(body.prompt).trim()) {
      throw new AppError('prompt is required when type is prompt', 400);
    }
  } else if (!body.file || typeof body.file !== 'object') {
    throw new AppError(
      'file is required for digital_twin and photo (object with type url | asset_id | base64 per HeyGen v3)',
      400
    );
  }
}

const listAvatarGroups = asyncHandler(async (req, res) => {
  const data = await heygenV3Service.listAvatarGroups(req.query);
  return successResponse(req, res, data, 200, messages.HEYGEN_AVATAR_GROUPS_OK);
});

const listAvatarLooks = asyncHandler(async (req, res) => {
  const data = await heygenV3Service.listAvatarLooks(req.query);
  return successResponse(req, res, data, 200, messages.HEYGEN_AVATAR_LOOKS_OK);
});

const createAvatar = asyncHandler(async (req, res) => {
  const { error, value } = createAvatarBodySchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: false,
  });
  if (error) {
    throw new AppError(
      error.details.map((d) => d.message.replace(/"/g, '')),
      400
    );
  }
  assertCreateAvatarPayload(value);
  const data = await heygenV3Service.createAvatar(value);
  return successResponse(req, res, data, 200, messages.HEYGEN_AVATAR_CREATED);
});

const createAvatarConsent = asyncHandler(async (req, res) => {
  const { groupId } = req.params;
  const data = await heygenV3Service.createAvatarConsent(groupId, req.body || {});
  return successResponse(req, res, data, 200, messages.HEYGEN_CONSENT_OK);
});

const listVoices = asyncHandler(async (req, res) => {
  const data = await heygenV3Service.listVoices(req.query);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICES_OK);
});

const designVoice = asyncHandler(async (req, res) => {
  const data = await heygenV3Service.designVoice(req.body);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_DESIGNED);
});

const cloneVoice = asyncHandler(async (req, res) => {
  const { audio } = req.body;
  if (!audio || typeof audio !== 'object' || !audio.type) {
    throw new AppError(
      'audio is required with type (HeyGen union: { type, url } | { type, asset_id } | { type, base64, media_type, data })',
      400
    );
  }
  const data = await heygenV3Service.cloneVoice(req.body);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_CLONE_STARTED);
});

const getVoice = asyncHandler(async (req, res) => {
  const data = await heygenV3Service.getVoice(req.params.voiceId);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_DETAIL_OK);
});

const previewSpeech = asyncHandler(async (req, res) => {
  const payload = {
    text: req.body.text,
    voice_id: req.body.voice_id,
    input_type: req.body.input_type || 'text',
    speed: req.body.speed,
    language: req.body.language,
    locale: req.body.locale,
  };
  Object.keys(payload).forEach((k) => payload[k] === undefined && delete payload[k]);
  const data = await heygenV3Service.generateSpeechPreview(payload);
  return successResponse(req, res, data, 200, messages.HEYGEN_SPEECH_PREVIEW_OK);
});

module.exports = {
  listAvatarGroups,
  listAvatarLooks,
  createAvatar,
  createAvatarConsent,
  listVoices,
  designVoice,
  cloneVoice,
  getVoice,
  previewSpeech,
};
