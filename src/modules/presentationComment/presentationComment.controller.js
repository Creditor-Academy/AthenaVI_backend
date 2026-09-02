const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const shareService = require('../presentationShare/presentationShare.service');
const rateLimit = require('../presentationShare/presentationShare.rateLimit.service');
const commentService = require('./presentationComment.service');

/**
 * Query values reach the controller as raw strings: Express 5 exposes `req.query` through a
 * getter, so the Joi-converted copy that `validate` assigns back never sticks. Validation
 * still rejects bad input; only the coercion is lost, so redo it here.
 */
function asBool(value) {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false') return false;
  return undefined;
}

const asLimit = (value) => (value === undefined ? undefined : Number(value));

/* =========================
   Editor (Bearer + workspace member)
========================= */

/** The parent router already proved membership, so the editor caller is always a member. */
const editorCaller = (req) => ({
  userId: req.user.id,
  role: req.workspaceMembership?.role || null,
  isMember: true,
  guestSessionId: null,
  guestDisplayName: null,
  surface: 'editor',
});

const listComments = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const { limit, cursor, slideId, resolved, orphaned } = req.query;

  const data = await commentService.listComments({
    workspaceId,
    projectId: presentationId,
    caller: editorCaller(req),
    limit: asLimit(limit),
    cursor,
    slideId,
    resolved: asBool(resolved),
    orphaned: asBool(orphaned) === true,
  });

  return successResponse(req, res, data, 200, messages.COMMENTS_FETCHED);
});

const createComment = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const comment = await commentService.createComment({
    workspaceId,
    projectId: presentationId,
    caller: editorCaller(req),
    payload: req.body,
  });
  return successResponse(req, res, { comment }, 201, messages.COMMENT_CREATED);
});

const updateComment = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, commentId } = req.params;
  const comment = await commentService.updateComment({
    workspaceId,
    projectId: presentationId,
    commentId,
    caller: editorCaller(req),
    payload: req.body,
  });
  return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
});

const deleteComment = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, commentId } = req.params;
  const data = await commentService.deleteComment({
    workspaceId,
    projectId: presentationId,
    commentId,
    caller: editorCaller(req),
  });
  return successResponse(req, res, data, 200, messages.COMMENT_DELETED);
});

const resolveComment = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, commentId } = req.params;
  const comment = await commentService.setResolved({
    workspaceId,
    projectId: presentationId,
    commentId,
    caller: editorCaller(req),
    resolved: true,
  });
  return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
});

const unresolveComment = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId, commentId } = req.params;
  const comment = await commentService.setResolved({
    workspaceId,
    projectId: presentationId,
    commentId,
    caller: editorCaller(req),
    resolved: false,
  });
  return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
});

const getMentionableUsers = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await commentService.getMentionableUsers({
    workspaceId,
    projectId: presentationId,
    query: req.query.q,
  });
  return successResponse(req, res, data, 200, messages.MENTIONABLE_USERS_FETCHED);
});

/* =========================
   Public capability token
========================= */

/**
 * A share-link caller may be a guest, a logged-in outsider, or a member who happened to open
 * the public URL. Only the member gets mention and resolve rights.
 */
function publicCaller(req, { canOpenInEditor, role }) {
  return {
    userId: req.user?.id || null,
    role: canOpenInEditor ? role : null,
    isMember: canOpenInEditor,
    guestSessionId: req.body?.viewerSessionId || req.query?.viewerSessionId || null,
    guestDisplayName: req.body?.displayName || null,
    surface: 'public',
  };
}

async function resolveWrite(req) {
  const { token } = req.params;
  await rateLimit.assertCommentWriteAllowed({
    ip: req.ip,
    tokenHash: shareService.hashToken(token),
  });

  const context = await shareService.resolveShareForComments({ token, user: req.user || null });
  if (!context.canComment) {
    throw new AppError(messages.PRESENTATION_COMMENT_DISABLED, 403);
  }
  return context;
}

const listPublicComments = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertCommentReadAllowed({ ip: req.ip });

  const context = await shareService.resolveShareForComments({
    token: req.params.token,
    user: req.user || null,
  });

  // A view-only link still answers 200 with an empty list, so the viewer page can render
  // without branching on an error.
  if (!context.canComment) {
    return successResponse(
      req,
      res,
      { comments: [], nextCursor: null },
      200,
      messages.COMMENTS_FETCHED
    );
  }

  const { limit, cursor, slideId, resolved } = req.query;
  const data = await commentService.listComments({
    workspaceId: context.share.workspaceId,
    projectId: context.share.projectId,
    caller: publicCaller(req, context),
    limit: asLimit(limit),
    cursor,
    slideId,
    resolved: asBool(resolved),
  });

  return successResponse(req, res, data, 200, messages.COMMENTS_FETCHED);
});

const createPublicComment = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const context = await resolveWrite(req);

  const comment = await commentService.createComment({
    workspaceId: context.share.workspaceId,
    projectId: context.share.projectId,
    caller: publicCaller(req, context),
    payload: req.body,
  });

  return successResponse(req, res, { comment }, 201, messages.COMMENT_CREATED);
});

const updatePublicComment = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const context = await resolveWrite(req);

  const comment = await commentService.updateComment({
    workspaceId: context.share.workspaceId,
    projectId: context.share.projectId,
    commentId: req.params.commentId,
    caller: publicCaller(req, context),
    payload: req.body,
  });

  return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
});

const deletePublicComment = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const context = await resolveWrite(req);

  const data = await commentService.deleteComment({
    workspaceId: context.share.workspaceId,
    projectId: context.share.projectId,
    commentId: req.params.commentId,
    caller: publicCaller(req, context),
  });

  return successResponse(req, res, data, 200, messages.COMMENT_DELETED);
});

const setPublicResolved = (resolved) =>
  asyncHandler(async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const context = await resolveWrite(req);

    const comment = await commentService.setResolved({
      workspaceId: context.share.workspaceId,
      projectId: context.share.projectId,
      commentId: req.params.commentId,
      caller: publicCaller(req, context),
      resolved,
    });

    return successResponse(req, res, { comment }, 200, messages.COMMENT_UPDATED);
  });

/**
 * Members opening the public URL get the mention picker; guests must not be able to read the
 * workspace roster, so for them this route does not exist.
 */
const getPublicMentionableUsers = asyncHandler(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertCommentReadAllowed({ ip: req.ip });

  const context = await shareService.resolveShareForComments({
    token: req.params.token,
    user: req.user || null,
  });
  if (!context.canOpenInEditor) {
    throw new AppError(messages.PRESENTATION_SHARE_NOT_FOUND, 404);
  }

  const data = await commentService.getMentionableUsers({
    workspaceId: context.share.workspaceId,
    projectId: context.share.projectId,
    query: req.query.q,
  });

  return successResponse(req, res, data, 200, messages.MENTIONABLE_USERS_FETCHED);
});

module.exports = {
  listComments,
  createComment,
  updateComment,
  deleteComment,
  resolveComment,
  unresolveComment,
  getMentionableUsers,
  listPublicComments,
  createPublicComment,
  updatePublicComment,
  deletePublicComment,
  resolvePublicComment: setPublicResolved(true),
  unresolvePublicComment: setPublicResolved(false),
  getPublicMentionableUsers,
};
