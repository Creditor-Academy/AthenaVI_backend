const prisma = require('../../shared/config/prismaClient');

/**
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.avatarGroupId
 * @param {string|null|undefined} params.avatarId
 * @param {string|null|undefined} params.name
 * @param {string} params.type
 * @param {string} [params.status]
 * @param {object|null} [params.raw]
 */
async function recordAvatar({
  userId,
  avatarGroupId,
  avatarId = null,
  name = null,
  type,
  status = 'processing',
  raw = null,
}) {
  return prisma.heygenAvatar.upsert({
    where: {
      userId_avatarGroupId: { userId, avatarGroupId },
    },
    create: {
      userId,
      avatarGroupId,
      avatarId: avatarId ?? null,
      name: name ?? null,
      type,
      status,
      raw,
    },
    update: {
      avatarId: avatarId ?? undefined,
      name: name !== undefined ? name : undefined,
      type,
      status,
      raw: raw !== undefined ? raw : undefined,
    },
  });
}

/**
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.voiceId
 * @param {string|null|undefined} params.name
 * @param {string} params.source - 'select' | 'clone'
 * @param {string|null|undefined} params.language
 * @param {object|null} [params.raw]
 */
async function recordVoice({
  userId,
  voiceId,
  name = null,
  source,
  language = null,
  raw = null,
}) {
  return prisma.heygenVoice.upsert({
    where: {
      userId_voiceId: { userId, voiceId },
    },
    create: {
      userId,
      voiceId,
      name: name ?? null,
      source,
      language: language ?? null,
      raw,
    },
    update: {
      name: name !== undefined ? name : undefined,
      source,
      language: language !== undefined ? language : undefined,
      raw: raw !== undefined ? raw : undefined,
    },
  });
}

async function listAvatarGroupIdsForUser(userId) {
  const rows = await prisma.heygenAvatar.findMany({
    where: { userId },
    select: { avatarGroupId: true },
  });
  return rows.map((r) => r.avatarGroupId);
}

async function listVoiceIdsForUser(userId) {
  const rows = await prisma.heygenVoice.findMany({
    where: { userId },
    select: { voiceId: true },
  });
  return rows.map((r) => r.voiceId);
}

async function userOwnsAvatarGroup(userId, groupId) {
  if (!groupId) return false;
  const row = await prisma.heygenAvatar.findUnique({
    where: {
      userId_avatarGroupId: { userId, avatarGroupId: groupId },
    },
    select: { id: true },
  });
  return Boolean(row);
}

async function userOwnsVoice(userId, voiceId) {
  if (!voiceId) return false;
  const row = await prisma.heygenVoice.findFirst({
    where: { userId, voiceId },
    select: { id: true },
  });
  return Boolean(row);
}

/** Clone voices are user-specific; block other users from detail when a clone row exists for someone else. */
async function cloneVoiceOwnedByOtherUser(userId, voiceId) {
  if (!voiceId) return false;
  const row = await prisma.heygenVoice.findFirst({
    where: { voiceId, source: 'clone' },
    select: { userId: true },
  });
  return Boolean(row && row.userId !== userId);
}

module.exports = {
  recordAvatar,
  recordVoice,
  listAvatarGroupIdsForUser,
  listVoiceIdsForUser,
  userOwnsAvatarGroup,
  userOwnsVoice,
  cloneVoiceOwnedByOtherUser,
};
