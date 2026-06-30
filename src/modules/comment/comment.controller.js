const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const commentService = require('./comment.service');

const listComments = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const { limit, cursor } = req.query;
  const result = await commentService.listComments(workspaceId, projectId, {
    limit: limit ? Number(limit) : undefined,
    cursor,
  });
  return successResponse(req, res, result, 200, messages.COMMENTS_FETCHED);
});

const createComment = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const comment = await commentService.createComment(
    workspaceId,
    projectId,
    req.user.id,
    req.body
  );
  return successResponse(req, res, { comment }, 201, messages.COMMENT_CREATED);
});

const updateComment = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, commentId } = req.params;
  const comment = await commentService.updateComment(
    workspaceId,
    projectId,
    commentId,
    req.user.id,
    req.body
  );
  return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
});

const deleteComment = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, commentId } = req.params;
  const result = await commentService.deleteComment(
    workspaceId,
    projectId,
    commentId,
    req.user.id,
    req.workspaceMembership.role
  );
  return successResponse(req, res, result, 200, messages.COMMENT_DELETED);
});

const getMentionableUsers = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const { q } = req.query;
  const result = await commentService.getMentionableUsers(workspaceId, projectId, q);
  return successResponse(req, res, result, 200, messages.MENTIONABLE_USERS_FETCHED);
});

module.exports = {
  listComments,
  createComment,
  updateComment,
  deleteComment,
  getMentionableUsers,
};
