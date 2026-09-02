const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const workspaceDao = require('../workspace/workspace.dao');
const inboxService = require('../inbox/inbox.service');
const commentDao = require('./presentationComment.dao');
const { touchComments } = require('./presentationComment.activity');

const ANONYMOUS_LABEL = 'Anonymous viewer';
const DELETED_AUTHOR_LABEL = 'Deleted user';

/** Spam guards. Threads are a discussion aid, not a data store. */
const MAX_ROOTS_PER_SLIDE = 100;
const MAX_REPLIES_PER_ROOT = 50;

/**
 * Identity of whoever is calling, normalized across the two surfaces so the rules below read
 * the same for a member in the editor and a guest on a share link.
 *
 * @typedef {object} Caller
 * @property {string|null} userId       set when a Bearer token resolved to a live session
 * @property {string|null} role         workspace role, or null when the caller is not a member
 * @property {boolean} isMember         workspace member: may mention and resolve
 * @property {string|null} guestSessionId    client-generated id, doubles as guest authorship proof
 * @property {string|null} guestDisplayName  guest-supplied name; ignored for logged-in callers
 * @property {'editor'|'public'} surface     `public` hides non-READY slides and orphaned threads
 */

/**
 * `authorId` and the guest pair are mutually exclusive. A logged-in caller always writes
 * `authorId` (even with a blank profile name, which merely displays as anonymous), so a user
 * who later renames does not leave a stale copy of their name on every comment.
 */
function resolveAuthorship(caller) {
  if (caller.userId) {
    return { authorId: caller.userId, guestSessionId: null, guestDisplayName: null };
  }

  const displayName = String(caller.guestDisplayName || '').trim();
  if (!caller.guestSessionId || !displayName) {
    throw new AppError(messages.PRESENTATION_COMMENT_GUEST_NAME_REQUIRED, 400);
  }

  return {
    authorId: null,
    guestSessionId: caller.guestSessionId,
    guestDisplayName: displayName,
  };
}

/**
 * `authorId` is SET NULL when a user is deleted, which is what distinguishes a departed
 * member (no author relation, no guest session) from a guest.
 */
function serializeAuthor(row) {
  if (row.author) {
    const name = String(row.author.name || '').trim();
    return {
      id: row.author.id,
      name: name || ANONYMOUS_LABEL,
      profileImage: row.author.profileImage || null,
      isAnonymous: !name,
    };
  }

  if (row.guestSessionId) {
    return {
      id: null,
      name: row.guestDisplayName || ANONYMOUS_LABEL,
      profileImage: null,
      isAnonymous: true,
    };
  }

  return { id: null, name: DELETED_AUTHOR_LABEL, profileImage: null, isAnonymous: false };
}

function serializeComment(row) {
  const out = {
    id: row.id,
    slideId: row.slideId,
    parentId: row.parentId,
    body: row.body,
    mentionedUserIds: row.mentionedUserIds || [],
    resolvedAt: row.resolvedAt || null,
    author: serializeAuthor(row),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };

  if (row.parentId === null) {
    out.replies = (row.replies || []).map(serializeComment);
  }

  return out;
}

async function loadPresentationOrThrow(workspaceId, projectId) {
  const project = await commentDao.findPresentationForComments(workspaceId, projectId);
  if (!project || !project.deck) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }
  return project;
}

const slidesOf = (project) => project.deck.slides || [];

/** Public callers only ever see slides the deck payload actually served them. */
const visibleSlideIds = (project, caller) =>
  slidesOf(project)
    .filter((s) => caller.surface !== 'public' || s.status === 'READY')
    .map((s) => s.id);

function assertSlideVisible(project, caller, slideId) {
  const slide = slidesOf(project).find((s) => s.id === slideId);
  if (!slide) {
    throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }
  if (caller.surface === 'public' && slide.status !== 'READY') {
    throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }
  return slide;
}

function normalizeMentionedUserIds(mentionedUserIds, caller) {
  // Only members can mention: a guest or an outside viewer must not be able to probe or
  // notify the workspace roster.
  if (!caller.isMember) {
    return [];
  }
  const unique = [...new Set((mentionedUserIds || []).filter(Boolean))];
  return unique.filter((id) => id !== caller.userId);
}

async function validateMentionedUsers(workspaceId, mentionedUserIds) {
  if (!mentionedUserIds.length) return;
  const memberIds = await commentDao.findWorkspaceMemberUserIds(workspaceId);
  const invalid = mentionedUserIds.filter((id) => !memberIds.has(id));
  if (invalid.length) {
    throw new AppError(messages.COMMENT_INVALID_MENTIONS, 400);
  }
}

function isAuthor(row, caller) {
  if (caller.userId) {
    return row.author?.id === caller.userId;
  }
  return Boolean(
    row.guestSessionId && caller.guestSessionId && row.guestSessionId === caller.guestSessionId
  );
}

const isWorkspaceAdmin = (caller) => caller.role === 'OWNER' || caller.role === 'ADMIN';

/**
 * A comment the caller cannot see must 404 rather than 403, so a share link cannot be used
 * to probe for threads on hidden slides.
 */
function assertCommentVisible(row, project, caller) {
  if (caller.surface !== 'public') return;

  if (!row.slideId) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  const slide = slidesOf(project).find((s) => s.id === row.slideId);
  if (!slide || slide.status !== 'READY') {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
}

async function listComments({ workspaceId, projectId, caller, limit = 50, cursor, slideId, resolved, orphaned = false }) {
  const project = await loadPresentationOrThrow(workspaceId, projectId);

  // Orphaned threads (slide deleted or wiped by a full regenerate) are an editor-only
  // recovery view; a guest never had those slides to begin with.
  if (orphaned && caller.surface === 'public') {
    return { comments: [], nextCursor: null };
  }

  if (slideId && caller.surface === 'public') {
    const slide = slidesOf(project).find((s) => s.id === slideId);
    if (!slide || slide.status !== 'READY') {
      return { comments: [], nextCursor: null };
    }
  }

  const result = await commentDao.listRootComments({
    projectId,
    slideId: slideId || null,
    slideIds: !slideId && caller.surface === 'public' ? visibleSlideIds(project, caller) : null,
    orphaned,
    resolved,
    limit,
    cursor,
  });

  return {
    comments: result.comments.map(serializeComment),
    nextCursor: result.nextCursor,
  };
}

async function createComment({ workspaceId, projectId, caller, payload }) {
  const project = await loadPresentationOrThrow(workspaceId, projectId);
  const authorship = resolveAuthorship(caller);

  let slideId = payload.slideId || null;
  let parentId = null;
  let parentRow = null;

  if (payload.parentId) {
    parentRow = await commentDao.findRootWithReplyCount(projectId, payload.parentId);
    if (!parentRow) {
      throw new AppError(messages.COMMENT_NOT_FOUND, 404);
    }
    assertCommentVisible(parentRow, project, caller);

    if (parentRow.parentId || parentRow.resolvedAt) {
      throw new AppError(messages.PRESENTATION_COMMENT_PARENT_INVALID, 400);
    }
    if (parentRow._count.replies >= MAX_REPLIES_PER_ROOT) {
      throw new AppError(messages.PRESENTATION_COMMENT_LIMIT, 400);
    }

    parentId = parentRow.id;
    slideId = parentRow.slideId;
  } else {
    if (!slideId) {
      throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
    }
    assertSlideVisible(project, caller, slideId);

    const roots = await commentDao.countRootsForSlide(projectId, slideId);
    if (roots >= MAX_ROOTS_PER_SLIDE) {
      throw new AppError(messages.PRESENTATION_COMMENT_LIMIT, 400);
    }
  }

  const mentionedUserIds = normalizeMentionedUserIds(payload.mentionedUserIds, caller);
  await validateMentionedUsers(workspaceId, mentionedUserIds);

  const comment = await commentDao.createComment({
    projectId,
    workspaceId,
    slideId,
    parentId,
    body: payload.body,
    mentionedUserIds,
    ...authorship,
  });

  await touchComments(projectId);
  await notify({
    comment,
    project,
    workspaceId,
    caller,
    newMentionIds: mentionedUserIds,
    parentRow,
    isCreate: true,
  });

  return serializeComment(comment);
}

async function updateComment({ workspaceId, projectId, commentId, caller, payload }) {
  const project = await loadPresentationOrThrow(workspaceId, projectId);
  const existing = await commentDao.findCommentById(projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  assertCommentVisible(existing, project, caller);

  if (!isAuthor(existing, caller)) {
    throw new AppError(messages.COMMENT_FORBIDDEN, 403);
  }

  const mentionedUserIds = normalizeMentionedUserIds(payload.mentionedUserIds, caller);
  await validateMentionedUsers(workspaceId, mentionedUserIds);

  const previousMentions = new Set(existing.mentionedUserIds || []);
  const newMentionIds = mentionedUserIds.filter((id) => !previousMentions.has(id));

  const comment = await commentDao.updateComment(commentId, {
    body: payload.body,
    mentionedUserIds,
  });

  await touchComments(projectId);
  if (newMentionIds.length) {
    await notify({
      comment,
      project,
      workspaceId,
      caller,
      newMentionIds,
      parentRow: null,
      isCreate: false,
    });
  }

  return serializeComment(comment);
}

async function deleteComment({ workspaceId, projectId, commentId, caller }) {
  const project = await loadPresentationOrThrow(workspaceId, projectId);
  const existing = await commentDao.findCommentById(projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  assertCommentVisible(existing, project, caller);

  if (!isAuthor(existing, caller) && !isWorkspaceAdmin(caller)) {
    throw new AppError(messages.COMMENT_FORBIDDEN, 403);
  }

  await commentDao.softDeleteThread(commentId, existing.parentId === null);
  await touchComments(projectId);

  return { deleted: true };
}

/** Resolve / reopen is a moderation action, so it stays with workspace members. */
async function setResolved({ workspaceId, projectId, commentId, caller, resolved }) {
  const project = await loadPresentationOrThrow(workspaceId, projectId);

  if (!caller.isMember) {
    throw new AppError(messages.PRESENTATION_COMMENT_RESOLVE_FORBIDDEN, 403);
  }

  const existing = await commentDao.findCommentById(projectId, commentId);
  if (!existing) {
    throw new AppError(messages.COMMENT_NOT_FOUND, 404);
  }
  assertCommentVisible(existing, project, caller);

  if (existing.parentId !== null) {
    throw new AppError(messages.PRESENTATION_COMMENT_PARENT_INVALID, 400);
  }

  const comment = await commentDao.updateComment(commentId, {
    resolvedAt: resolved ? new Date() : null,
    resolvedBy: resolved ? caller.userId : null,
  });

  await touchComments(projectId);
  return serializeComment(comment);
}

async function getMentionableUsers({ workspaceId, projectId, query }) {
  await loadPresentationOrThrow(workspaceId, projectId);
  const users = await commentDao.findMentionableUsers(workspaceId, query || undefined);
  return { users };
}

/** Inbox fan-out never breaks a comment write; the comment is the user's actual intent. */
async function notify({ comment, project, workspaceId, caller, newMentionIds, parentRow, isCreate }) {
  try {
    const workspace = await workspaceDao.findWorkspaceById(workspaceId);

    await inboxService.notifyPresentationComment({
      comment,
      project,
      workspace,
      authorName: serializeAuthor(comment).name,
      authorUserId: caller.userId || null,
      newMentionIds,
      parentAuthorId: parentRow?.author?.id || null,
      isCreate,
    });
  } catch (err) {
    logger.error('presentation_comment_notify_failed', {
      commentId: comment.id,
      error: err?.message,
    });
  }
}

module.exports = {
  MAX_ROOTS_PER_SLIDE,
  MAX_REPLIES_PER_ROOT,
  serializeComment,
  listComments,
  createComment,
  updateComment,
  deleteComment,
  setResolved,
  getMentionableUsers,
};
