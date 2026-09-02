const prisma = require('../../shared/config/prismaClient');

const authorSelect = {
  id: true,
  name: true,
  profileImage: true,
};

const commentInclude = {
  author: { select: authorSelect },
};

/** Replies are always returned with their root, oldest first (reading order). */
const repliesInclude = {
  replies: {
    where: { deletedAt: null },
    orderBy: { createdAt: 'asc' },
    include: commentInclude,
  },
};

/**
 * Ownership guard for every comment route: the project must exist, be a presentation, and
 * live in this workspace. Slide ids come along so the service can validate `slideId` and
 * hide comments on slides that are not READY from the public surface.
 */
const findPresentationForComments = (workspaceId, projectId) => {
  return prisma.project.findFirst({
    where: { id: projectId, workspaceId, type: 'PRESENTATION' },
    select: {
      id: true,
      name: true,
      workspaceId: true,
      createdBy: true,
      deck: {
        select: {
          id: true,
          status: true,
          slides: { select: { id: true, order: true, status: true } },
        },
      },
    },
  });
};

/**
 * Cursor pagination over root threads only; replies ride along on each root so the client
 * renders a whole thread without a second call.
 * @param {{ projectId: string, slideId?: string|null, slideIds?: string[]|null, orphaned?: boolean, resolved?: boolean, limit: number, cursor?: string }} params
 */
const listRootComments = async ({
  projectId,
  slideId,
  slideIds,
  orphaned = false,
  resolved,
  limit,
  cursor,
}) => {
  const where = {
    projectId,
    parentId: null,
    deletedAt: null,
  };

  if (orphaned) {
    where.slideId = null;
  } else if (slideId) {
    where.slideId = slideId;
  } else if (Array.isArray(slideIds)) {
    where.slideId = { in: slideIds };
  } else {
    where.slideId = { not: null };
  }

  if (resolved === true) {
    where.resolvedAt = { not: null };
  } else if (resolved === false) {
    where.resolvedAt = null;
  }

  if (cursor) {
    const cursorRow = await prisma.presentationComment.findFirst({
      where: { id: cursor, projectId },
      select: { createdAt: true },
    });
    if (cursorRow) {
      where.createdAt = { lt: cursorRow.createdAt };
    }
  }

  const rows = await prisma.presentationComment.findMany({
    where,
    include: { ...commentInclude, ...repliesInclude },
    orderBy: { createdAt: 'desc' },
    take: limit + 1,
  });

  const hasMore = rows.length > limit;
  const comments = hasMore ? rows.slice(0, limit) : rows;
  const nextCursor = hasMore ? comments[comments.length - 1].id : null;

  return { comments, nextCursor };
};

const findCommentById = (projectId, commentId) => {
  return prisma.presentationComment.findFirst({
    where: { id: commentId, projectId, deletedAt: null },
    include: commentInclude,
  });
};

const findRootWithReplyCount = (projectId, commentId) => {
  return prisma.presentationComment.findFirst({
    where: { id: commentId, projectId, deletedAt: null },
    include: {
      ...commentInclude,
      _count: { select: { replies: { where: { deletedAt: null } } } },
    },
  });
};

const findCommentWithReplies = (projectId, commentId) => {
  return prisma.presentationComment.findFirst({
    where: { id: commentId, projectId, deletedAt: null },
    include: { ...commentInclude, ...repliesInclude },
  });
};

const countRootsForSlide = (projectId, slideId) => {
  return prisma.presentationComment.count({
    where: { projectId, slideId, parentId: null, deletedAt: null },
  });
};

const createComment = (data) => {
  return prisma.presentationComment.create({
    data,
    include: { ...commentInclude, ...repliesInclude },
  });
};

const updateComment = (commentId, data) => {
  return prisma.presentationComment.update({
    where: { id: commentId },
    data,
    include: { ...commentInclude, ...repliesInclude },
  });
};

/**
 * Soft-delete a thread: the root and every live reply go together, so a deleted root never
 * leaves orphaned replies rendering without their parent.
 */
const softDeleteThread = async (commentId, isRoot) => {
  const deletedAt = new Date();

  if (!isRoot) {
    await prisma.presentationComment.update({
      where: { id: commentId },
      data: { deletedAt },
    });
    return;
  }

  await prisma.$transaction([
    prisma.presentationComment.update({
      where: { id: commentId },
      data: { deletedAt },
    }),
    prisma.presentationComment.updateMany({
      where: { parentId: commentId, deletedAt: null },
      data: { deletedAt },
    }),
  ]);
};

const findWorkspaceMemberUserIds = async (workspaceId) => {
  const members = await prisma.workspaceMember.findMany({
    where: { workspaceId },
    select: { userId: true },
  });
  return new Set(members.map((m) => m.userId));
};

const findMentionableUsers = async (workspaceId, query, limit = 20) => {
  const where = { workspaceId };
  if (query) {
    where.user = {
      OR: [
        { name: { contains: query, mode: 'insensitive' } },
        { email: { contains: query, mode: 'insensitive' } },
      ],
    };
  }

  const members = await prisma.workspaceMember.findMany({
    where,
    include: {
      user: { select: { id: true, name: true, email: true } },
    },
    take: limit,
    orderBy: { joinedAt: 'asc' },
  });

  return members.map((m) => m.user);
};

module.exports = {
  findPresentationForComments,
  listRootComments,
  findCommentById,
  findRootWithReplyCount,
  findCommentWithReplies,
  countRootsForSlide,
  createComment,
  updateComment,
  softDeleteThread,
  findWorkspaceMemberUserIds,
  findMentionableUsers,
};
