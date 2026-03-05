const workspaceDao = require('./workspace.dao');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const crypto = require('crypto');

const INVITATION_EXPIRY_DAYS = 7;
const MAX_WORKSPACE_NAME_LENGTH = 255;

async function createPrivateWorkspaceForUser(userId) {
  const existing = await workspaceDao.findPrivateWorkspaceByOwnerId(userId);
  if (existing) return existing;

  return await workspaceDao.transaction(async (tx) => {
    return await workspaceDao.createWorkspaceWithMember(
      tx,
      { name: 'Personal', type: 'PRIVATE', ownerId: userId },
      { userId, role: 'OWNER' }
    );
  });
}

async function createTeamWorkspace(userId, name) {
  if (!name || typeof name !== 'string' || !name.trim()) {
    throw new AppError(messages.WORKSPACE_NAME_REQUIRED, 400);
  }
  const trimmed = name.trim();
  if (trimmed.length > MAX_WORKSPACE_NAME_LENGTH) {
    throw new AppError('Workspace name is too long', 400);
  }

  return await workspaceDao.transaction(async (tx) => {
    return await workspaceDao.createWorkspaceWithMember(
      tx,
      { name: trimmed, type: 'TEAM', ownerId: userId },
      { userId, role: 'OWNER' }
    );
  });
}

async function getUserWorkspaces(userId) {
  return await workspaceDao.findWorkspacesByUserId(userId);
}

async function getWorkspaceById(userId, workspaceId) {
  const workspace = await workspaceDao.findWorkspaceById(workspaceId);
  if (!workspace) throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);

  const membership = await workspaceDao.findWorkspaceMember(workspaceId, userId);
  if (!membership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);

  return workspace;
}

async function deleteWorkspace(userId, workspaceId) {
  const workspace = await workspaceDao.findWorkspaceById(workspaceId);
  if (!workspace) throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  if (workspace.type === 'PRIVATE') {
    throw new AppError(messages.WORKSPACE_CANNOT_DELETE_PRIVATE, 400);
  }

  const membership = await workspaceDao.findWorkspaceMember(workspaceId, userId);
  if (!membership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  if (membership.role !== 'OWNER') {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  await workspaceDao.deleteWorkspace(workspaceId);
  return workspace;
}

async function inviteMember(workspaceId, inviterId, email, role) {
  if (!['ADMIN', 'MEMBER'].includes(role)) {
    throw new AppError(messages.WORKSPACE_INVITE_ROLE_INVALID, 400);
  }

  const inviterMembership = await workspaceDao.findWorkspaceMember(workspaceId, inviterId);
  if (!inviterMembership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  if (!['OWNER', 'ADMIN'].includes(inviterMembership.role)) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  const workspace = await workspaceDao.findWorkspaceById(workspaceId);
  if (!workspace) throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);

  const existingUser = await workspaceDao.findUserByEmail(email);
  if (existingUser) {
    const existingMember = await workspaceDao.findWorkspaceMember(workspaceId, existingUser.id);
    if (existingMember) {
      throw new AppError(messages.WORKSPACE_ALREADY_MEMBER, 409);
    }
  }

  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + INVITATION_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

  await workspaceDao.createInvitation({
    workspaceId,
    email: email.trim().toLowerCase(),
    role,
    token,
    status: 'PENDING',
    expiresAt,
  });

  return { token, expiresAt };
}

async function acceptInvitation(token, userId) {
  const invitation = await workspaceDao.findInvitationByToken(token);
  if (!invitation) throw new AppError(messages.WORKSPACE_INVITATION_EXPIRED, 400);
  if (invitation.status !== 'PENDING') {
    throw new AppError(messages.WORKSPACE_INVITATION_EXPIRED, 400);
  }
  if (invitation.expiresAt < new Date()) {
    throw new AppError(messages.WORKSPACE_INVITATION_EXPIRED, 400);
  }

  const user = await workspaceDao.findUserById(userId);
  if (!user) throw new AppError(messages.UNAUTHORIZED, 401);
  if (user.email.toLowerCase() !== invitation.email.toLowerCase()) {
    throw new AppError(messages.WORKSPACE_INVITATION_EMAIL_MISMATCH, 400);
  }

  const existingMember = await workspaceDao.findWorkspaceMember(invitation.workspaceId, userId);
  if (existingMember) {
    await workspaceDao.updateInvitationStatus(invitation.id, 'ACCEPTED');
    return existingMember.workspace;
  }

  await workspaceDao.createWorkspaceMember({
    workspaceId: invitation.workspaceId,
    userId,
    role: invitation.role,
  });
  await workspaceDao.updateInvitationStatus(invitation.id, 'ACCEPTED');

  return await workspaceDao.findWorkspaceById(invitation.workspaceId);
}

async function removeMember(workspaceId, requesterId, memberId) {
  const requesterMembership = await workspaceDao.findWorkspaceMember(workspaceId, requesterId);
  if (!requesterMembership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);

  const targetMember = await workspaceDao.findWorkspaceMemberById(memberId);
  if (!targetMember || targetMember.workspaceId !== workspaceId) {
    throw new AppError(messages.WORKSPACE_MEMBER_NOT_FOUND, 404);
  }

  const isSelf = requesterId === memberId;
  if (isSelf) {
    if (targetMember.role === 'OWNER') {
      throw new AppError(messages.WORKSPACE_OWNER_CANNOT_REMOVE_SELF, 400);
    }
  } else {
    if (!['OWNER', 'ADMIN'].includes(requesterMembership.role)) {
      throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
    }
    if (targetMember.role === 'OWNER') {
      const ownerCount = await workspaceDao.countOwnersInWorkspace(workspaceId);
      if (ownerCount <= 1) {
        throw new AppError(messages.WORKSPACE_LAST_OWNER, 400);
      }
    }
  }

  await workspaceDao.deleteMember(memberId);
  return targetMember;
}

async function changeMemberRole(workspaceId, requesterId, memberId, newRole) {
  const requesterMembership = await workspaceDao.findWorkspaceMember(workspaceId, requesterId);
  if (!requesterMembership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  if (requesterMembership.role !== 'OWNER') {
    throw new AppError(messages.WORKSPACE_ONLY_OWNER_CHANGE_ROLES, 403);
  }

  const targetMember = await workspaceDao.findWorkspaceMemberById(memberId);
  if (!targetMember || targetMember.workspaceId !== workspaceId) {
    throw new AppError(messages.WORKSPACE_MEMBER_NOT_FOUND, 404);
  }

  if (!['OWNER', 'ADMIN', 'MEMBER'].includes(newRole)) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  if (newRole === 'OWNER') {
    const ownerCount = await workspaceDao.countOwnersInWorkspace(workspaceId);
    if (ownerCount < 1) throw new AppError(messages.WORKSPACE_LAST_OWNER, 400);
    await workspaceDao.updateMemberRole(memberId, 'OWNER');
    if (requesterId !== memberId) {
      await workspaceDao.updateMemberRole(requesterMembership.id, 'ADMIN');
    }
  } else {
    if (targetMember.role === 'OWNER') {
      const ownerCount = await workspaceDao.countOwnersInWorkspace(workspaceId);
      if (ownerCount <= 1) {
        throw new AppError(messages.WORKSPACE_LAST_OWNER, 400);
      }
    }
    await workspaceDao.updateMemberRole(memberId, newRole);
  }

  return await workspaceDao.findWorkspaceMemberById(memberId);
}

async function getWorkspaceMembers(workspaceId, userId) {
  const membership = await workspaceDao.findWorkspaceMember(workspaceId, userId);
  if (!membership) throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);

  return await workspaceDao.findMembersByWorkspaceId(workspaceId);
}

module.exports = {
  createPrivateWorkspaceForUser,
  createTeamWorkspace,
  getUserWorkspaces,
  getWorkspaceById,
  deleteWorkspace,
  inviteMember,
  acceptInvitation,
  removeMember,
  changeMemberRole,
  getWorkspaceMembers,
};
