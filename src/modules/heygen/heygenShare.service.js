const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const heygenDao = require('./heygen.dao');
const heygenShareDao = require('./heygenShare.dao');
const heygenAccess = require('./heygenAccess.service');

async function getWorkspaceMemberRole(workspaceId, userId) {
  const member = await heygenShareDao.findWorkspaceMember(workspaceId, userId);
  return member?.role || null;
}

async function shareAvatarWithWorkspace({ userId, workspaceId, groupId }) {
  const avatarGroupId = String(groupId || '').trim();
  if (!avatarGroupId) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  const owns = await heygenDao.userOwnsAvatarGroup(userId, avatarGroupId);
  if (!owns) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  await heygenAccess.assertWorkspaceMember(userId, workspaceId);

  const share = await heygenShareDao.shareAvatarToWorkspace({
    workspaceId,
    sharedByUserId: userId,
    avatarGroupId,
  });

  return { share, avatarGroupId };
}

async function unshareAvatarFromWorkspace({ userId, workspaceId, groupId }) {
  const avatarGroupId = String(groupId || '').trim();
  if (!avatarGroupId) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  await heygenAccess.assertWorkspaceMember(userId, workspaceId);

  const owns = await heygenDao.userOwnsAvatarGroup(userId, avatarGroupId);
  const role = await getWorkspaceMemberRole(workspaceId, userId);
  const canManage = owns || role === 'OWNER' || role === 'ADMIN';
  if (!canManage) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  await heygenShareDao.unshareAvatarFromWorkspace({ workspaceId, avatarGroupId });
  return { avatarGroupId };
}

async function shareVoiceWithWorkspace({ userId, workspaceId, voiceId }) {
  const normalizedVoiceId = String(voiceId || '').trim();
  if (!normalizedVoiceId) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  const owns = await heygenDao.userOwnsVoice(userId, normalizedVoiceId);
  if (!owns) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  await heygenAccess.assertWorkspaceMember(userId, workspaceId);

  const share = await heygenShareDao.shareVoiceToWorkspace({
    workspaceId,
    sharedByUserId: userId,
    voiceId: normalizedVoiceId,
  });

  return { share, voiceId: normalizedVoiceId };
}

async function unshareVoiceFromWorkspace({ userId, workspaceId, voiceId }) {
  const normalizedVoiceId = String(voiceId || '').trim();
  if (!normalizedVoiceId) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  await heygenAccess.assertWorkspaceMember(userId, workspaceId);

  const owns = await heygenDao.userOwnsVoice(userId, normalizedVoiceId);
  const role = await getWorkspaceMemberRole(workspaceId, userId);
  const canManage = owns || role === 'OWNER' || role === 'ADMIN';
  if (!canManage) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  await heygenShareDao.unshareVoiceFromWorkspace({
    workspaceId,
    voiceId: normalizedVoiceId,
  });
  return { voiceId: normalizedVoiceId };
}

async function listSharedAvatars(workspaceId) {
  const shares = await heygenShareDao.listAvatarSharesForWorkspace(workspaceId);
  const groupIds = shares.map((row) => row.avatarGroupId).filter(Boolean);
  if (!groupIds.length) {
    return { avatars: [] };
  }

  const avatarRows = await prisma.heygenAvatar.findMany({
    where: { avatarGroupId: { in: groupIds } },
    select: {
      avatarGroupId: true,
      avatarId: true,
      name: true,
      type: true,
      status: true,
      userId: true,
      createdAt: true,
    },
  });
  const avatarByGroupId = new Map(avatarRows.map((row) => [row.avatarGroupId, row]));

  const avatars = shares
    .map((share) => {
      const avatar = avatarByGroupId.get(share.avatarGroupId);
      if (!avatar) return null;
      return {
        avatarGroupId: share.avatarGroupId,
        avatarId: avatar.avatarId,
        name: avatar.name,
        type: avatar.type,
        status: avatar.status,
        ownerUserId: avatar.userId,
        sharedByUserId: share.sharedByUserId,
        sharedAt: share.createdAt,
      };
    })
    .filter(Boolean);

  return { avatars };
}

async function listSharedVoices(workspaceId) {
  const shares = await heygenShareDao.listVoiceSharesForWorkspace(workspaceId);
  const voiceIds = shares.map((row) => row.voiceId).filter(Boolean);
  if (!voiceIds.length) {
    return { voices: [] };
  }

  const voiceRows = await prisma.heygenVoice.findMany({
    where: { voiceId: { in: voiceIds } },
    select: {
      voiceId: true,
      name: true,
      source: true,
      language: true,
      userId: true,
      createdAt: true,
    },
  });
  const voiceById = new Map(voiceRows.map((row) => [row.voiceId, row]));

  const voices = shares
    .map((share) => {
      const voice = voiceById.get(share.voiceId);
      if (!voice) return null;
      return {
        voiceId: share.voiceId,
        name: voice.name,
        source: voice.source,
        language: voice.language,
        ownerUserId: voice.userId,
        sharedByUserId: share.sharedByUserId,
        sharedAt: share.createdAt,
      };
    })
    .filter(Boolean);

  return { voices };
}

module.exports = {
  shareAvatarWithWorkspace,
  unshareAvatarFromWorkspace,
  shareVoiceWithWorkspace,
  unshareVoiceFromWorkspace,
  listSharedAvatars,
  listSharedVoices,
};
