const prisma = require('../../shared/config/prismaClient');

const RESOURCE_TYPES = Object.freeze({
  AVATAR: 'avatar',
  VOICE: 'voice',
});

async function findWorkspaceMember(workspaceId, userId) {
  return prisma.workspaceMember.findUnique({
    where: {
      workspaceId_userId: { workspaceId, userId },
    },
    select: { role: true },
  });
}

async function shareAvatarToWorkspace({ workspaceId, sharedByUserId, avatarGroupId }) {
  return prisma.heygenWorkspaceShare.upsert({
    where: {
      workspaceId_resourceType_avatarGroupId: {
        workspaceId,
        resourceType: RESOURCE_TYPES.AVATAR,
        avatarGroupId,
      },
    },
    create: {
      workspaceId,
      sharedByUserId,
      resourceType: RESOURCE_TYPES.AVATAR,
      avatarGroupId,
    },
    update: {
      sharedByUserId,
    },
  });
}

async function unshareAvatarFromWorkspace({ workspaceId, avatarGroupId }) {
  return prisma.heygenWorkspaceShare.deleteMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.AVATAR,
      avatarGroupId,
    },
  });
}

async function shareVoiceToWorkspace({ workspaceId, sharedByUserId, voiceId }) {
  return prisma.heygenWorkspaceShare.upsert({
    where: {
      workspaceId_resourceType_voiceId: {
        workspaceId,
        resourceType: RESOURCE_TYPES.VOICE,
        voiceId,
      },
    },
    create: {
      workspaceId,
      sharedByUserId,
      resourceType: RESOURCE_TYPES.VOICE,
      voiceId,
    },
    update: {
      sharedByUserId,
    },
  });
}

async function unshareVoiceFromWorkspace({ workspaceId, voiceId }) {
  return prisma.heygenWorkspaceShare.deleteMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.VOICE,
      voiceId,
    },
  });
}

async function deleteAllAvatarSharesForGroup(avatarGroupId) {
  if (!avatarGroupId) return;
  await prisma.heygenWorkspaceShare.deleteMany({
    where: {
      resourceType: RESOURCE_TYPES.AVATAR,
      avatarGroupId,
    },
  });
}

async function deleteAllVoiceSharesForVoice(voiceId) {
  if (!voiceId) return;
  await prisma.heygenWorkspaceShare.deleteMany({
    where: {
      resourceType: RESOURCE_TYPES.VOICE,
      voiceId,
    },
  });
}

async function listAvatarSharesForWorkspace(workspaceId) {
  return prisma.heygenWorkspaceShare.findMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.AVATAR,
    },
    orderBy: { createdAt: 'desc' },
  });
}

async function listVoiceSharesForWorkspace(workspaceId) {
  return prisma.heygenWorkspaceShare.findMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.VOICE,
    },
    orderBy: { createdAt: 'desc' },
  });
}

async function listSharedAvatarGroupIdsForWorkspace(workspaceId) {
  const rows = await prisma.heygenWorkspaceShare.findMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.AVATAR,
      avatarGroupId: { not: null },
    },
    select: {
      avatarGroupId: true,
      sharedByUserId: true,
    },
  });
  return rows;
}

async function listSharedVoiceIdsForWorkspace(workspaceId) {
  const rows = await prisma.heygenWorkspaceShare.findMany({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.VOICE,
      voiceId: { not: null },
    },
    select: {
      voiceId: true,
      sharedByUserId: true,
    },
  });
  return rows;
}

async function isAvatarGroupSharedToWorkspace(workspaceId, avatarGroupId) {
  if (!workspaceId || !avatarGroupId) return false;
  const row = await prisma.heygenWorkspaceShare.findFirst({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.AVATAR,
      avatarGroupId,
    },
    select: { id: true },
  });
  return Boolean(row);
}

async function isVoiceSharedToWorkspace(workspaceId, voiceId) {
  if (!workspaceId || !voiceId) return false;
  const row = await prisma.heygenWorkspaceShare.findFirst({
    where: {
      workspaceId,
      resourceType: RESOURCE_TYPES.VOICE,
      voiceId,
    },
    select: { id: true },
  });
  return Boolean(row);
}

async function findAvatarGroupOwnerUserId(avatarGroupId) {
  const row = await prisma.heygenAvatar.findFirst({
    where: { avatarGroupId },
    select: { userId: true },
    orderBy: { createdAt: 'asc' },
  });
  return row?.userId || null;
}

async function isAvatarGroupRegisteredPrivate(avatarGroupId) {
  const row = await prisma.heygenAvatar.findFirst({
    where: { avatarGroupId },
    select: { id: true },
  });
  return Boolean(row);
}

async function findVoiceOwnerUserId(voiceId) {
  const row = await prisma.heygenVoice.findFirst({
    where: { voiceId },
    select: { userId: true, source: true },
    orderBy: { createdAt: 'asc' },
  });
  return row;
}

module.exports = {
  RESOURCE_TYPES,
  findWorkspaceMember,
  shareAvatarToWorkspace,
  unshareAvatarFromWorkspace,
  deleteAllAvatarSharesForGroup,
  shareVoiceToWorkspace,
  unshareVoiceFromWorkspace,
  deleteAllVoiceSharesForVoice,
  listAvatarSharesForWorkspace,
  listVoiceSharesForWorkspace,
  listSharedAvatarGroupIdsForWorkspace,
  listSharedVoiceIdsForWorkspace,
  isAvatarGroupSharedToWorkspace,
  isVoiceSharedToWorkspace,
  findAvatarGroupOwnerUserId,
  isAvatarGroupRegisteredPrivate,
  findVoiceOwnerUserId,
};
