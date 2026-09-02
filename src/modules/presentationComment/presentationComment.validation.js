const Joi = require('joi');

/** Presentation ids are project uuids; slide and comment ids are cuids/uuids, so keep them loose. */
const workspaceIdParam = Joi.string().uuid().required();
const presentationIdParam = Joi.string().required();
const commentIdParam = Joi.string().uuid().required();
const slideIdField = Joi.string().trim().max(64);

/** base64url capability token, mirroring presentationShare.validations. */
const shareTokenParam = Joi.string()
  .trim()
  .min(16)
  .max(128)
  .pattern(/^[A-Za-z0-9_-]+$/)
  .required();

/** Guests prove authorship with the same localStorage id the presence heartbeat uses. */
const viewerSessionIdField = Joi.string()
  .trim()
  .min(8)
  .max(64)
  .pattern(/^[A-Za-z0-9_-]+$/);

const displayNameField = Joi.string().trim().min(1).max(80);

const bodyField = Joi.string().trim().min(1).max(4000).required();

const mentionUserIdsField = Joi.array()
  .items(Joi.string().uuid())
  .max(20)
  .unique()
  .optional()
  .default([]);

const listQuery = Joi.object({
  slideId: slideIdField.optional(),
  limit: Joi.number().integer().min(1).max(100).optional(),
  cursor: Joi.string().uuid().optional(),
  resolved: Joi.boolean().optional(),
  orphaned: Joi.boolean().optional(),
});

/** Either a root (`slideId`) or a reply (`parentId`), never both. */
const createBodyKeys = {
  body: bodyField,
  slideId: slideIdField.optional(),
  parentId: Joi.string().uuid().optional(),
  mentionedUserIds: mentionUserIdsField,
};

const updateBodyKeys = {
  body: bodyField,
  mentionedUserIds: mentionUserIdsField,
};

const guestBodyKeys = {
  viewerSessionId: viewerSessionIdField.optional(),
  displayName: displayNameField.optional(),
};

const noBody = Joi.object({}).unknown(false);
const noQuery = Joi.object({}).unknown(false);

/* =========================
   Editor (Bearer + workspace member)
========================= */

const editorParams = Joi.object({
  workspaceId: workspaceIdParam,
  presentationId: presentationIdParam,
});

const editorCommentParams = editorParams.keys({ commentId: commentIdParam });

const listCommentsSchema = Joi.object({
  params: editorParams,
  query: listQuery,
  body: noBody,
});

const createCommentSchema = Joi.object({
  params: editorParams,
  query: noQuery,
  body: Joi.object(createBodyKeys).xor('slideId', 'parentId').required(),
});

const updateCommentSchema = Joi.object({
  params: editorCommentParams,
  query: noQuery,
  body: Joi.object(updateBodyKeys).required(),
});

const commentIdSchema = Joi.object({
  params: editorCommentParams,
  query: noQuery,
  body: noBody,
});

const mentionableUsersSchema = Joi.object({
  params: editorParams,
  query: Joi.object({
    q: Joi.string().trim().max(100).optional().allow(''),
  }),
  body: noBody,
});

/* =========================
   Public capability token
========================= */

const publicParams = Joi.object({ token: shareTokenParam });
const publicCommentParams = publicParams.keys({ commentId: commentIdParam });

const publicListCommentsSchema = Joi.object({
  params: publicParams,
  query: listQuery,
  body: noBody,
});

const publicCreateCommentSchema = Joi.object({
  params: publicParams,
  query: noQuery,
  body: Joi.object({ ...createBodyKeys, ...guestBodyKeys })
    .xor('slideId', 'parentId')
    .required(),
});

const publicUpdateCommentSchema = Joi.object({
  params: publicCommentParams,
  query: noQuery,
  body: Joi.object({ ...updateBodyKeys, ...guestBodyKeys }).required(),
});

/** Guests identify themselves on delete too, so the body stays optional but typed. */
const publicDeleteCommentSchema = Joi.object({
  params: publicCommentParams,
  query: Joi.object({
    viewerSessionId: viewerSessionIdField.optional(),
  }),
  body: Joi.object(guestBodyKeys).optional().default({}),
});

const publicCommentIdSchema = Joi.object({
  params: publicCommentParams,
  query: noQuery,
  body: Joi.object(guestBodyKeys).optional().default({}),
});

const publicMentionableUsersSchema = Joi.object({
  params: publicParams,
  query: Joi.object({
    q: Joi.string().trim().max(100).optional().allow(''),
  }),
  body: noBody,
});

module.exports = {
  listCommentsSchema,
  createCommentSchema,
  updateCommentSchema,
  commentIdSchema,
  mentionableUsersSchema,
  publicListCommentsSchema,
  publicCreateCommentSchema,
  publicUpdateCommentSchema,
  publicDeleteCommentSchema,
  publicCommentIdSchema,
  publicMentionableUsersSchema,
};
