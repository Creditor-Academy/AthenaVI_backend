const prisma = require('../../shared/config/prismaClient');

/* =========================
   WORKSPACE
========================= */

const findPrivateWorkspaceByOwnerId = async (ownerId) => {
  return await prisma.workspace.findFirst({
    where: {
      ownerId,
      type: 'PRIVATE',
    },
  });
};

const createWorkspace = async (data) => {
  return await prisma.workspace.create({
    data,
  });
};

/** Use inside dao.transaction(tx => createWorkspaceWithMember(tx, ...)) */
const createWorkspaceWithMember = async (tx, workspaceData, memberData) => {
  const workspace = await tx.workspace.create({
    data: workspaceData,
  });
  await tx.workspaceMember.create({
    data: {
      workspaceId: workspace.id,
      userId: memberData.userId,
      role: memberData.role,
    },
  });
  return workspace;
};

const transaction = (fn) => prisma.$transaction(fn);

const findWorkspaceById = async (workspaceId) => {
  return await prisma.workspace.findUnique({
    where: { id: workspaceId },
    include: {
      owner: { select: { id: true, email: true, name: true } },
    },
  });
};

const findWorkspacesByUserId = async (userId) => {
  return await prisma.workspace.findMany({
    where: {
      members: {
        some: { userId },
      },
    },
    include: {
      owner: { select: { id: true, email: true, name: true } },
      members: {
        where: { userId },
        select: { role: true, joinedAt: true },
      },
    },
    orderBy: { updatedAt: 'desc' },
  });
};

const deleteWorkspace = async (workspaceId) => {
  return await prisma.workspace.delete({
    where: { id: workspaceId },
  });
};

/* =========================
   WORKSPACE MEMBER
========================= */

const createWorkspaceMember = async (data) => {
  return await prisma.workspaceMember.create({
    data,
  });
};

const findWorkspaceMember = async (workspaceId, userId) => {
  return await prisma.workspaceMember.findUnique({
    where: {
      workspaceId_userId: { workspaceId, userId },
    },
    include: {
      workspace: true,
      user: { select: { id: true, email: true, name: true } },
    },
  });
};

const findWorkspaceMemberById = async (memberId) => {
  return await prisma.workspaceMember.findUnique({
    where: { id: memberId },
    include: {
      workspace: true,
      user: { select: { id: true, email: true, name: true } },
    },
  });
};

const findMembersByWorkspaceId = async (workspaceId) => {
  return await prisma.workspaceMember.findMany({
    where: { workspaceId },
    include: {
      user: { select: { id: true, email: true, name: true } },
    },
    orderBy: { joinedAt: 'asc' },
  });
};

const countOwnersInWorkspace = async (workspaceId) => {
  return await prisma.workspaceMember.count({
    where: {
      workspaceId,
      role: 'OWNER',
    },
  });
};

const updateMemberRole = async (memberId, role) => {
  return await prisma.workspaceMember.update({
    where: { id: memberId },
    data: { role },
  });
};

const deleteMember = async (memberId) => {
  return await prisma.workspaceMember.delete({
    where: { id: memberId },
  });
};

/* =========================
   INVITATION
========================= */

const createInvitation = async (data) => {
  return await prisma.invitation.create({
    data,
  });
};

const findInvitationByToken = async (token) => {
  return await prisma.invitation.findUnique({
    where: { token },
    include: { workspace: true },
  });
};

const updateInvitationStatus = async (invitationId, status) => {
  return await prisma.invitation.update({
    where: { id: invitationId },
    data: { status },
  });
};

/* =========================
   USER (for workspace context: invite check, accept email match)
========================= */

const findUserByEmail = async (email) => {
  return await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, name: true },
  });
};

const findUserById = async (userId) => {
  return await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, name: true },
  });
};

module.exports = {
  findPrivateWorkspaceByOwnerId,
  createWorkspace,
  createWorkspaceWithMember,
  transaction,
  findWorkspaceById,
  findWorkspacesByUserId,
  deleteWorkspace,
  createWorkspaceMember,
  findWorkspaceMember,
  findWorkspaceMemberById,
  findMembersByWorkspaceId,
  countOwnersInWorkspace,
  updateMemberRole,
  deleteMember,
  createInvitation,
  findInvitationByToken,
  updateInvitationStatus,
  findUserByEmail,
  findUserById,
};
