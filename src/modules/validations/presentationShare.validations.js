const Joi = require('joi');

const workspaceIdParam = Joi.string().uuid().required();
const presentationIdParam = Joi.string().required();

/** base64url capability token (32 random bytes -> 43 chars); range allows future rotation sizes. */
const shareTokenParam = Joi.string()
  .trim()
  .min(16)
  .max(128)
  .pattern(/^[A-Za-z0-9_-]+$/)
  .required();

const viewerSessionIdField = Joi.string()
  .trim()
  .min(8)
  .max(64)
  .pattern(/^[A-Za-z0-9_-]+$/)
  .required();

const slideIndexField = Joi.number().integer().min(0).max(10000).default(0);

const shareByPresentationSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
});

const patchShareSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    enabled: Joi.boolean().optional(),
    expiresAt: Joi.date().iso().allow(null).optional(),
  })
    .min(1)
    .required(),
});

const publicShareTokenSchema = Joi.object({
  params: Joi.object({
    token: shareTokenParam,
  }),
});

/** `displayName` is intentionally absent: identity is server-computed, never client-supplied. */
const publicPresenceHeartbeatSchema = Joi.object({
  params: Joi.object({
    token: shareTokenParam,
  }),
  body: Joi.object({
    viewerSessionId: viewerSessionIdField,
    slideIndex: slideIndexField,
  }).required(),
});

const publicPresenceLeaveSchema = Joi.object({
  params: Joi.object({
    token: shareTokenParam,
  }),
  query: Joi.object({
    viewerSessionId: viewerSessionIdField,
  }),
});

module.exports = {
  shareByPresentationSchema,
  patchShareSchema,
  publicShareTokenSchema,
  publicPresenceHeartbeatSchema,
  publicPresenceLeaveSchema,
};
