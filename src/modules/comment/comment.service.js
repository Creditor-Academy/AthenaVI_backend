const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const projectDao = require('../project/project.dao');
const workspaceDao = require('../workspace/workspace.dao');
const commentDao = require('./comment.dao');
const inboxService = require('../inbox/inbox.service');

const MAX_REPLIES_PER_ROOT = 50;

function serializeComment(row) {
  const out = {
    id: row.id,
    parentId: row.parentId || null,
    body: row.body,
    mentionedUserIds: row.mentionedUserIds,
    resolvedAt: row.resolvedAt || null,
    resolvedBy: row.resolvedBy || null,
    author: row.author,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
  if (row.parentId == null) {
    out.replies = (row.replies || []).map(serializeComment);
  }
  return out;
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
  const mentionedUserIds = normalizeMentionedUserIds(payload.mentionedUserIds, authorId);
  await validateMentionedUsers(workspaceId, mentionedUserIds);

  let parentId;
  let parentRow = null;
  if (payload.parentId) {
    parentRow = await commentDao.findRootWithReplyCount(projectId, payload.parentId);
    if (!parentRow || parentRow.workspaceId !== workspaceId) {
      throw new AppError(messages.COMMENT_NOT_FOUND, 404);
    }
    if (parentRow.parentId) {
      throw new AppError(messages.COMMENT_PARENT_INVALID, 400);
    }
    if (parentRow.resolvedAt) {
      throw new AppError(messages.COMMENT_PARENT_INVALID, 400);
    }
    if (parentRow._count.replies >= MAX_REPLIES_PER_ROOT) {
      throw new AppError(messages.COMMENT_REPLY_LIMIT, 400);
    }
    parentId = parentRow.id;
  }

  const commentData = {
    workspaceId,
    projectId,
    authorId,
    body: payload.body,
    mentionedUserIds,
  };
  if (parentId) {
    commentData.parentId = parentId;
  }

  let comment;
  try {
    comment = await commentDao.createComment(commentData);
  } catch (err) {
    logger.error('project_comment_create_failed', {
      error: err.message,
      code: err.code,
      meta: err.meta,
    });
    throw err;
  }

  try {
    const workspace = await workspaceDao.findWorkspaceById(workspaceId);
    await inboxService.notifyProjectComment({
      comment,
      project,
      author: comment.author,
      workspace,
      newMentionIds: mentionedUserIds,
      isCreate: true,
    });
  } catch (notifyErr) {
    logger.warn('Project comment created but inbox notify failed', {
      commentId: comment.id,
      error: notifyErr.message,
    });
  }

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

  if (newMentionIds.length) {
    try {
      const project = await getProjectOrThrow(workspaceId, projectId);
      const workspace = await workspaceDao.findWorkspaceById(workspaceId);
      await inboxService.notifyProjectComment({
        comment,
        project,
        author: comment.author,
        workspace,
        newMentionIds,
        isCreate: false,
      });
    } catch (notifyErr) {
      logger.warn('Project comment updated but inbox notify failed', {
        commentId: comment.id,
        error: notifyErr.message,
      });
    }
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

  if (!existing.parentId) {
    await commentDao.softDeleteReplies(existing.id);
  }
  await commentDao.softDeleteComment(commentId);
  return { deleted: true };
}

async function setResolved(workspaceId, projectId, commentId, userId, resolved) {
  await getProjectOrThrow(workspaceId, projectId);
  const existing = await commentDao.findCommentById(workspaceId, projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  if (existing.parentId) {
    throw new AppError(messages.COMMENT_PARENT_INVALID, 400);
  }

  const comment = await commentDao.updateComment(commentId, {
    resolvedAt: resolved ? new Date() : null,
    resolvedBy: resolved ? userId : null,
  });

  return serializeComment(comment);
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
  setResolved,
  getMentionableUsers,
};
