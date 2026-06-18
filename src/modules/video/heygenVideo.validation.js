const Joi = require('joi');
const { avatarEngineField } = require('../../shared/validations/heygenFields');

const workspaceProjectParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  projectId: Joi.string().uuid().required(),
});

const voiceSettingsSchema = Joi.object({
  speed: Joi.number().min(0.5).max(1.5).optional(),
  pitch: Joi.number().min(-50).max(50).optional(),
  volume: Joi.number().min(0).max(2).optional(),
  locale: Joi.string().trim().max(32).optional(),
  engine_settings: Joi.object().unknown(true).optional(),
}).optional();

const createHeygenVideoSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    sceneId: Joi.string().trim().min(1).max(256).required(),
    avatarId: Joi.string().trim().required(),
    title: Joi.string().trim().min(1).max(500).required(),
    resolution: Joi.string().trim().valid('1080p', '720p').required(),
    aspectRatio: Joi.string().trim().valid('16:9', '9:16').required(),
    backgroundColor: Joi.string().trim().pattern(/^#[0-9A-Fa-f]{6}$/).required(),
    voiceId: Joi.string().trim().required(),
    script: Joi.string().trim().min(1).required(),
    /**
     * HeyGen rendering engine: avatar_iv (default) or avatar_v.
     * Omit or send "" when the look has supported_api_engines: [].
     */
    avatarEngine: avatarEngineField(),
    /** HeyGen: photo_avatar only (Avatar IV). Omit for studio_avatar / digital_twin or HeyGen returns 400. */
    avatarType: Joi.string()
      .trim()
      .valid('studio_avatar', 'digital_twin', 'photo_avatar')
      .optional(),
    /** Avatar IV + photo_avatar only; ignored for avatar_v. */
    expressiveness: Joi.string().trim().valid('low', 'medium', 'high').optional(),
    voiceSettings: voiceSettingsSchema,
    removeBackground: Joi.boolean().optional(),
    outputFormat: Joi.string().trim().valid('mp4', 'webm').optional(),
  }).required(),
});

const emptyBody = Joi.object({}).unknown(false).default({});

const listHeygenVideosSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

const heygenVideoIdParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  projectId: Joi.string().uuid().required(),
  heygenVideoId: Joi.string().uuid().required(),
});

const getHeygenVideoSchema = Joi.object({
  params: heygenVideoIdParams,
  query: Joi.object({
    /**
     * false — DB row only (fast poll).
     * true (default) — refresh HeyGen status; when completed, expose HeyGen CDN URL immediately and queue S3 in background.
     * full — wait for S3 copy (legacy / render-safe).
     */
    sync: Joi.string().valid('false', 'true', 'status', 'full').optional(),
  }).unknown(false),
  body: emptyBody,
});

const downloadHeygenVideoSchema = Joi.object({
  params: heygenVideoIdParams,
  query: Joi.object({
    expiresIn: Joi.number().integer().min(60).max(3600).optional(),
  }).unknown(false),
  body: emptyBody,
});

const getS3LocationSchema = Joi.object({
  params: heygenVideoIdParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

/** GET/HEAD stream — browsers may send Range query via Range header (not validated here). */
const getStreamSchema = Joi.object({
  params: heygenVideoIdParams,
  query: Joi.object({}).unknown(false),
  body: emptyBody,
});

module.exports = {
  createHeygenVideoSchema,
  listHeygenVideosSchema,
  getHeygenVideoSchema,
  downloadHeygenVideoSchema,
  getS3LocationSchema,
  getStreamSchema,
};
