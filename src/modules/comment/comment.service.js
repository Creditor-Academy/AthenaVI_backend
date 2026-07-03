const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('../project/project.dao');
const workspaceDao = require('../workspace/workspace.dao');
const commentDao = require('./comment.dao');
const inboxService = require('../inbox/inbox.service');

function serializeComment(row) {
  return {
    id: row.id,
    body: row.body,
    mentionedUserIds: row.mentionedUserIds,
    author: row.author,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

async function getProjectOrThrow(workspaceId, projectId) {
  const project = await projectDao.findProjectById(workspaceId, projectId);
  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }
  return project;
}

function normalizeMentionedUserIds(mentionedUserIds, authorId) {
  const unique = [...new Set((mentionedUserIds || []).filter(Boolean))];
  return unique.filter((id) => id !== authorId);
}

async function validateMentionedUsers(workspaceId, mentionedUserIds) {
  if (!mentionedUserIds.length) {
    return;
  }
  const memberIds = await commentDao.findWorkspaceMemberUserIds(workspaceId);
  const invalid = mentionedUserIds.filter((id) => !memberIds.has(id));
  if (invalid.length) {
    throw new AppError(messages.COMMENT_INVALID_MENTIONS, 400);
  }
}

async function listComments(workspaceId, projectId, { limit = 50, cursor } = {}) {
  await getProjectOrThrow(workspaceId, projectId);
  const result = await commentDao.listComments({
    workspaceId,
    projectId,
    limit,
    cursor,
  });
  return {
    comments: result.comments.map(serializeComment),
    nextCursor: result.nextCursor,
  };
}

async function createComment(workspaceId, projectId, authorId, payload) {
  const project = await getProjectOrThrow(workspaceId, projectId);
  const workspace = await workspaceDao.findWorkspaceById(workspaceId);
  const mentionedUserIds = normalizeMentionedUserIds(payload.mentionedUserIds, authorId);
  await validateMentionedUsers(workspaceId, mentionedUserIds);

  const comment = await commentDao.createComment({
    workspaceId,
    projectId,
    authorId,
    body: payload.body,
    mentionedUserIds,
  });

  const author = comment.author;
  await inboxService.notifyProjectComment({
    comment,
    project,
    author,
    workspace,
    newMentionIds: mentionedUserIds,
    isCreate: true,
  });

  return serializeComment(comment);
}

async function updateComment(workspaceId, projectId, commentId, authorId, payload) {
  await getProjectOrThrow(workspaceId, projectId);
  const existing = await commentDao.findCommentById(workspaceId, projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  if (existing.authorId !== authorId) {
    throw new AppError(messages.COMMENT_FORBIDDEN, 403);
  }

  const mentionedUserIds = normalizeMentionedUserIds(payload.mentionedUserIds, authorId);
  await validateMentionedUsers(workspaceId, mentionedUserIds);

  const previousMentions = new Set(existing.mentionedUserIds || []);
  const newMentionIds = mentionedUserIds.filter((id) => !previousMentions.has(id));

  const comment = await commentDao.updateComment(commentId, {
    body: payload.body,
    mentionedUserIds,
  });

  const project = await getProjectOrThrow(workspaceId, projectId);
  const workspace = await workspaceDao.findWorkspaceById(workspaceId);

  if (newMentionIds.length) {
    await inboxService.notifyProjectComment({
      comment,
      project,
      author: comment.author,
      workspace,
      newMentionIds,
      isCreate: false,
    });
  }

  return serializeComment(comment);
}

async function deleteComment(workspaceId, projectId, commentId, userId, membershipRole) {
  await getProjectOrThrow(workspaceId, projectId);
  const existing = await commentDao.findCommentById(workspaceId, projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }

  const isAuthor = existing.authorId === userId;
  const isAdmin = membershipRole === 'OWNER' || membershipRole === 'ADMIN';
  if (!isAuthor && !isAdmin) {
    throw new AppError(messages.COMMENT_FORBIDDEN, 403);
  }

  await commentDao.softDeleteComment(commentId);
  return { deleted: true };
}

async function getMentionableUsers(workspaceId, projectId, query) {
  await getProjectOrThrow(workspaceId, projectId);
  const users = await commentDao.findMentionableUsers(workspaceId, query || undefined);
  return { users };
}

module.exports = {
  listComments,
  createComment,
  updateComment,
  deleteComment,
  getMentionableUsers,
};
