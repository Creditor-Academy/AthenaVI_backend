const prisma = require('../../shared/config/prismaClient');

const authorSelect = {
  id: true,
  name: true,
  profileImage: true,
};

const createComment = async (data) => {
  return prisma.projectComment.create({
    data,
    include: { author: { select: authorSelect } },
  });
};

const findCommentById = async (workspaceId, projectId, commentId) => {
  return prisma.projectComment.findFirst({
    where: {
      id: commentId,
      workspaceId,
      projectId,
      deletedAt: null,
    },
    include: { author: { select: authorSelect } },
  });
};

const listComments = async ({ workspaceId, projectId, limit, cursor }) => {
  const where = {
    workspaceId,
    projectId,
    deletedAt: null,
  };

  if (cursor) {
    const cursorRow = await prisma.projectComment.findFirst({
      where: { id: cursor, workspaceId, projectId, deletedAt: null },
      select: { createdAt: true },
    });
    if (cursorRow) {
      where.createdAt = { lt: cursorRow.createdAt };
    }
  }

  const rows = await prisma.projectComment.findMany({
    where,
    include: { author: { select: authorSelect } },
    orderBy: { createdAt: 'desc' },
    take: limit + 1,
  });

  const hasMore = rows.length > limit;
  const comments = hasMore ? rows.slice(0, limit) : rows;
  const nextCursor = hasMore ? comments[comments.length - 1].id : null;

  return { comments, nextCursor };
};

const updateComment = async (commentId, data) => {
  return prisma.projectComment.update({
    where: { id: commentId },
    data,
    include: { author: { select: authorSelect } },
  });
};

const softDeleteComment = async (commentId) => {
  return prisma.projectComment.update({
    where: { id: commentId },
    data: { deletedAt: new Date() },
  });
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
  createComment,
  findCommentById,
  listComments,
  updateComment,
  softDeleteComment,
  findWorkspaceMemberUserIds,
  findMentionableUsers,
};
