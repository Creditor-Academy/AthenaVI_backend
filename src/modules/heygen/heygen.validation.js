const Joi = require('joi');

const listAvatarGroupsQuery = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    ownership: Joi.string().valid('public', 'private'),
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
    limit: Joi.number().integer().min(1).max(50),
    token: Joi.string().allow('', null),
  }).unknown(true),
});

const listVoicesQuery = Joi.object({
  body: Joi.object({}).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    type: Joi.string().valid('public', 'private'),
    engine: Joi.string().allow('', null),
    language: Joi.string().allow('', null),
    gender: Joi.string().valid('male', 'female'),
    limit: Joi.number().integer().min(1).max(100),
    token: Joi.string().allow('', null),
  }).unknown(true),
});

const designVoiceBody = Joi.object({
  body: Joi.object({
    prompt: Joi.string().min(1).max(1000).required(),
    gender: Joi.string().valid('male', 'female').allow(null, ''),
    locale: Joi.string().allow(null, ''),
    seed: Joi.number().integer().min(0),
  }).unknown(false),
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
});

const cloneVoiceBody = Joi.object({
  body: Joi.object({
    voice_name: Joi.string().min(1).max(100).required(),
    audio: Joi.object().unknown(true).required(),
    language: Joi.string().allow(null, ''),
    remove_background_noise: Joi.boolean(),
  }).unknown(false),
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
  cloneVoiceBody,
  getVoiceParams,
  createAvatarConsentBody,
  previewSpeechBody,
  createAvatarBodySchema,
};
