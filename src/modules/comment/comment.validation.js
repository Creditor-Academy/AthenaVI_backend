const Joi = require('joi');

const workspaceProjectParams = Joi.object({
  workspaceId: Joi.string().uuid().required(),
  projectId: Joi.string().uuid().required(),
});

const mentionUserIdsSchema = Joi.array()
  .items(Joi.string().uuid())
  .max(20)
  .unique()
  .optional()
  .default([]);

const listCommentsSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({
    limit: Joi.number().integer().min(1).max(100).optional(),
    cursor: Joi.string().uuid().optional(),
  }),
  body: Joi.object({}).unknown(false),
});

const createCommentSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    body: Joi.string().trim().min(1).max(4000).required(),
    mentionedUserIds: mentionUserIdsSchema,
    parentId: Joi.string().uuid().optional(),
  }).required(),
});

const updateCommentSchema = Joi.object({
  params: workspaceProjectParams.keys({
    commentId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    body: Joi.string().trim().min(1).max(4000).required(),
    mentionedUserIds: mentionUserIdsSchema,
  }).required(),
});

const commentIdSchema = Joi.object({
  params: workspaceProjectParams.keys({
    commentId: Joi.string().uuid().required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const mentionableUsersSchema = Joi.object({
  params: workspaceProjectParams,
  query: Joi.object({
    q: Joi.string().trim().max(100).optional().allow(''),
  }),
  body: Joi.object({}).unknown(false),
});

module.exports = {
  listCommentsSchema,
  createCommentSchema,
  updateCommentSchema,
  commentIdSchema,
  mentionableUsersSchema,
};
