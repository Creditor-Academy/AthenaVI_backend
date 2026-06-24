const Joi = require('joi');

const listAvatarGroupsQuery = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    ownership: Joi.string().valid('public', 'private'),
    workspace_id: Joi.string().uuid().optional(),
    limit: Joi.number().integer().min(1).max(50),
    token: Joi.string().allow('', null),
  }).unknown(true),
});

const listAvatarLooksQuery = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    group_id: Joi.string().allow('', null),
    avatar_type: Joi.string().valid('studio_avatar', 'digital_twin', 'photo_avatar'),
    ownership: Joi.string().valid('public', 'private'),
    workspace_id: Joi.string().uuid().optional(),
    limit: Joi.number().integer().min(1).max(50),
    token: Joi.string().allow('', null),
  }).unknown(true),
});

const listVoicesQuery = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    type: Joi.string().valid('public', 'private'),
    workspace_id: Joi.string().uuid().optional(),
    engine: Joi.string().allow('', null),
    language: Joi.string().allow('', null),
    gender: Joi.string().valid('male', 'female'),
    limit: Joi.number().integer().min(1).max(100),
    token: Joi.string().allow('', null),
  }).unknown(true),
});

const designVoiceBody = Joi.object({
  body: Joi.object({
    prompt: Joi.string().min(1).max(1000),
    gender: Joi.string().valid('male', 'female').allow(null, ''),
    locale: Joi.string().allow(null, ''),
    seed: Joi.number().integer().min(0),
    voiceId: Joi.string().min(1),
    voice_id: Joi.string().min(1),
  })
    .unknown(true)
    .custom((value, helpers) => {
      const hasPrompt = value.prompt != null && String(value.prompt).trim() !== '';
      const hasVoiceId =
        (value.voiceId != null && String(value.voiceId).trim() !== '') ||
        (value.voice_id != null && String(value.voice_id).trim() !== '');
      if (hasVoiceId && !hasPrompt) {
        return helpers.message(
          'voice_id belongs on POST /api/heygen/voices/select, not on voice design (POST /api/heygen/voices requires prompt)'
        );
      }
      if (!hasPrompt) {
        return helpers.message('prompt is required for voice design (HeyGen POST /v3/voices)');
      }
      return value;
    }),
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
});

const selectVoiceBody = Joi.object({
  body: Joi.object({
    voiceId: Joi.string().min(1),
    voice_id: Joi.string().min(1),
  })
    .or('voiceId', 'voice_id')
    .unknown(true)
    .custom((value, helpers) => {
      const voiceId = (value.voiceId || value.voice_id || '').trim();
      if (!voiceId) {
        return helpers.message('voice_id or voiceId is required');
      }
      return { voiceId };
    }),
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
});

const cloneVoiceBody = Joi.object({
  body: Joi.object({
    voice_name: Joi.string().min(1).max(100),
    voiceName: Joi.string().min(1).max(100),
    audio: Joi.object().unknown(true).required(),
    language: Joi.string().allow(null, ''),
    remove_background_noise: Joi.boolean(),
    removeBackgroundNoise: Joi.boolean(),
  })
    .or('voice_name', 'voiceName')
    .unknown(true)
    .custom((value, helpers) => {
      const voice_name = (value.voice_name || value.voiceName || '').trim();
      if (!voice_name) {
        return helpers.message('voice_name or voiceName is required (HeyGen POST /v3/voices/clone)');
      }
      if (!value.audio || typeof value.audio !== 'object' || !value.audio.type) {
        return helpers.message(
          'audio is required with type: url | asset_id | base64 (HeyGen POST /v3/voices/clone)'
        );
      }
      const payload = { voice_name, audio: value.audio };
      if (value.language != null && String(value.language).trim() !== '') {
        payload.language = String(value.language).trim();
      }
      const rbn = value.remove_background_noise ?? value.removeBackgroundNoise;
      if (rbn !== undefined) payload.remove_background_noise = Boolean(rbn);
      return payload;
    }),
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
});

const getVoiceParams = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({
    voiceId: Joi.string().required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const createAvatarConsentBody = Joi.object({
  body: Joi.object({
    reroute_url: Joi.string().uri().allow(null, ''),
  }).unknown(false),
  params: Joi.object({
    groupId: Joi.string().required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const deleteAvatarGroupParams = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({
    groupId: Joi.string().trim().min(1).required(),
  }).unknown(false),
  query: Joi.object({
    voice_id: Joi.string().trim().allow('', null),
  }).unknown(false),
});

const deleteAvatarLookParams = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({
    lookId: Joi.string().trim().min(1).required(),
  }).unknown(false),
  query: Joi.object({
    voice_id: Joi.string().trim().allow('', null),
  }).unknown(false),
});

const deleteVoiceParams = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({
    voiceId: Joi.string().required(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const previewSpeechBody = Joi.object({
  body: Joi.object({
    text: Joi.string().min(1).max(5000).required(),
    voice_id: Joi.string().required(),
    input_type: Joi.string().valid('text', 'ssml'),
    speed: Joi.number().min(0.5).max(2),
    language: Joi.string().allow(null, ''),
    locale: Joi.string().allow(null, ''),
  }).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
});

const createAvatarBodySchema = Joi.object({
  type: Joi.string().valid('digital_twin', 'photo', 'prompt').required(),
  name: Joi.string().max(200).required(),
  file: Joi.object().unknown(true),
  prompt: Joi.string().max(1000).allow('', null),
  reference_images: Joi.array().items(Joi.object().unknown(true)).max(20),
  avatar_group_id: Joi.string().allow(null, ''),
})
  .unknown(true)
  .prefs({ stripUnknown: false });

module.exports = {
  listAvatarGroupsQuery,
  listAvatarLooksQuery,
  listVoicesQuery,
  designVoiceBody,
  selectVoiceBody,
  cloneVoiceBody,
  getVoiceParams,
  deleteAvatarGroupParams,
  deleteAvatarLookParams,
  deleteVoiceParams,
  createAvatarConsentBody,
  previewSpeechBody,
  createAvatarBodySchema,
};
