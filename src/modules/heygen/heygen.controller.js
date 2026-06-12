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
const userCreditBilling = require('../credit/userCreditBilling');
const { truncateText } = require('../credit/creditHistory.enrich');
const { FEATURE } = require('../../shared/config/creditPricing');

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
  const userId = req.user.id;
  const data = await heygenV3Service.listAvatarGroups(userId, req.query);
  return successResponse(req, res, data, 200, messages.HEYGEN_AVATAR_GROUPS_OK);
});

const listAvatarLooks = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const data = await heygenV3Service.listAvatarLooks(userId, req.query);
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
  const userId = req.user.id;
  await userCreditBilling.assertUserCanAffordFeature(userId, FEATURE.AVATAR_CREATE);
  const data = await heygenV3Service.createAvatar(userId, value);
  const groupId = heygenV3Service.extractAvatarGroupIdFromCreateResponse(data);
  await userCreditBilling.chargeUserFeature({
    userId,
    feature: FEATURE.AVATAR_CREATE,
    idempotencyKey: groupId ? `heygen-avatar:${groupId}` : `heygen-avatar:${userId}:${Date.now()}`,
    reference: groupId,
    extraMetadata: {
      avatarGroupId: groupId || null,
      avatarName: value.name,
      avatarType: value.type,
    },
  });
  return successResponse(req, res, data, 200, messages.HEYGEN_AVATAR_CREATED);
});

const createAvatarConsent = asyncHandler(async (req, res) => {
  const { groupId } = req.params;
  const userId = req.user.id;
  const data = await heygenV3Service.createAvatarConsent(userId, groupId, req.body || {});
  return successResponse(req, res, data, 200, messages.HEYGEN_CONSENT_OK);
});

const listVoices = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const data = await heygenV3Service.listVoices(userId, req.query);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICES_OK);
});

const designVoice = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  await userCreditBilling.assertUserCanAffordFeature(userId, FEATURE.VOICE_DESIGN);
  const data = await heygenV3Service.designVoice(userId, req.body);
  const voiceId =
    data?.data?.voice_id ?? data?.data?.id ?? data?.voice_id ?? `design-${Date.now()}`;
  await userCreditBilling.chargeUserFeature({
    userId,
    feature: FEATURE.VOICE_DESIGN,
    idempotencyKey: `heygen-voice-design:${userId}:${voiceId}`,
    reference: String(voiceId),
    extraMetadata: {
      voiceId: String(voiceId),
      promptPreview: truncateText(req.body?.prompt),
    },
  });
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_DESIGNED);
});

const selectVoice = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const data = await heygenV3Service.selectVoice(userId, req.body.voiceId);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICES_OK);
});

const cloneVoice = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  await userCreditBilling.assertUserCanAffordFeature(userId, FEATURE.VOICE_CLONE);
  const data = await heygenV3Service.cloneVoice(userId, req.body);
  const voiceId = data?.voiceId ?? data?.voiceCloneId ?? `clone-${Date.now()}`;
  const voiceName = req.body?.voice_name || req.body?.voiceName || null;
  await userCreditBilling.chargeUserFeature({
    userId,
    feature: FEATURE.VOICE_CLONE,
    idempotencyKey: `heygen-voice-clone:${voiceId}`,
    reference: String(voiceId),
    extraMetadata: {
      voiceId: String(voiceId),
      voiceName: voiceName ? String(voiceName).trim() : null,
    },
  });
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_CLONE_STARTED);
});

const getVoice = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const data = await heygenV3Service.getVoice(userId, req.params.voiceId);
  return successResponse(req, res, data, 200, messages.HEYGEN_VOICE_DETAIL_OK);
});

const previewSpeech = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const payload = {
    text: req.body.text,
    voice_id: req.body.voice_id,
    input_type: req.body.input_type || 'text',
    speed: req.body.speed,
    language: req.body.language,
    locale: req.body.locale,
  };
  Object.keys(payload).forEach((k) => payload[k] === undefined && delete payload[k]);
  const estimate = await userCreditBilling.assertUserCanAffordFeature(
    userId,
    FEATURE.VOICE_PREVIEW,
    { text: payload.text }
  );
  const data = await heygenV3Service.generateSpeechPreview(payload);
  const durationSeconds = estimate.breakdown?.durationSeconds ?? 0;
  await userCreditBilling.chargeUserFeature({
    userId,
    feature: FEATURE.VOICE_PREVIEW,
    idempotencyKey: `heygen-voice-preview:${userId}:${payload.voice_id}:${Date.now()}`,
    durationSeconds,
    reference: payload.voice_id,
    extraMetadata: {
      voiceId: payload.voice_id,
      previewText: truncateText(payload.text, 200),
    },
  });
  return successResponse(req, res, data, 200, messages.HEYGEN_SPEECH_PREVIEW_OK);
});

module.exports = {
  listAvatarGroups,
  listAvatarLooks,
  createAvatar,
  createAvatarConsent,
  listVoices,
  designVoice,
  selectVoice,
  cloneVoice,
  getVoice,
  previewSpeech,
};
