const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const heygenV3Service = require('./heygenV3.service');
const {
  HEYGEN_AVATAR_PHOTO_MIMES,
  HEYGEN_AVATAR_TWIN_MIMES,
} = require('../../middlewares/heygenAvatarCreate.middleware');
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

function payloadFromMultipart(req) {
  if (!req.file?.buffer) return null;

  const type = req.body.type != null ? String(req.body.type).trim() : '';
  const name = req.body.name != null ? String(req.body.name).trim() : '';

  if (!type || !name) {
    throw new AppError('type and name are required when uploading a file', 400);
  }
  if (type === 'prompt') {
    throw new AppError(
      'Prompt avatars cannot include an uploaded file; use application/json without a file',
      400
    );
  }
  if (type !== 'photo' && type !== 'digital_twin') {
    throw new AppError('Uploaded file is only supported for type photo or digital_twin', 400);
  }

  const mime = req.file.mimetype;
  if (type === 'photo' && !HEYGEN_AVATAR_PHOTO_MIMES.has(mime)) {
    throw new AppError('Photo avatar file must be image/jpeg, image/png, or image/webp', 400);
  }
  if (type === 'digital_twin' && !HEYGEN_AVATAR_TWIN_MIMES.has(mime)) {
    throw new AppError(
      'Digital twin file must be image/jpeg, image/png, image/webp, video/mp4, or video/webm',
      400
    );
  }

  let reference_images;
  const rawRef = req.body.reference_images;
  if (rawRef != null && rawRef !== '') {
    try {
      reference_images =
        typeof rawRef === 'string' ? JSON.parse(rawRef) : rawRef;
    } catch {
      throw new AppError('reference_images must be valid JSON when provided', 400);
    }
  }

  const payload = {
    type,
    name,
    file: {
      type: 'base64',
      media_type: mime,
      data: req.file.buffer.toString('base64'),
    },
  };

  const avatar_group_id = req.body.avatar_group_id;
  if (avatar_group_id !== undefined && avatar_group_id !== null && avatar_group_id !== '') {
    payload.avatar_group_id = avatar_group_id;
  }
  if (reference_images !== undefined) {
    payload.reference_images = reference_images;
  }

  return payload;
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
  const fromMultipart = payloadFromMultipart(req);
  const source = fromMultipart ?? req.body;

  const { error, value } = createAvatarBodySchema.validate(source, {
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
