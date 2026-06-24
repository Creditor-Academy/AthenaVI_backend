const prisma = require('../../shared/config/prismaClient');
const { getJson } = require('../../shared/services/heygenV3.client');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const heygenDao = require('./heygen.dao');
const heygenShareDao = require('./heygenShare.dao');

function normalizeWorkspaceId(workspaceId) {
  if (workspaceId == null) return null;
  const trimmed = String(workspaceId).trim();
  return trimmed || null;
}

async function assertWorkspaceMember(userId, workspaceId) {
  const workspace = await prisma.workspace.findUnique({
    where: { id: workspaceId },
    include: { members: true },
  });
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }
  if (workspace.type === 'PRIVATE') {
    if (workspace.ownerId !== userId) {
      throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
    }
    return workspace;
  }
  const isMember = workspace.members.some((member) => member.userId === userId);
  if (!isMember) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }
  return workspace;
}

async function buildAllowedAvatarGroupContext(userId, workspaceId) {
  const ownIds = await heygenDao.listAvatarGroupIdsForUser(userId);
  const ownSet = new Set(ownIds);
  const allowed = new Set(ownIds);
  const sharedMetaByGroupId = new Map();

  const normalizedWorkspaceId = normalizeWorkspaceId(workspaceId);
  if (!normalizedWorkspaceId) {
    return { allowed, ownSet, sharedMetaByGroupId };
  }

  await assertWorkspaceMember(userId, normalizedWorkspaceId);
  const sharedRows = await heygenShareDao.listSharedAvatarGroupIdsForWorkspace(normalizedWorkspaceId);
  for (const row of sharedRows) {
    if (!row.avatarGroupId) continue;
    allowed.add(row.avatarGroupId);
    if (!ownSet.has(row.avatarGroupId)) {
      sharedMetaByGroupId.set(row.avatarGroupId, {
        shared: true,
        sharedByUserId: row.sharedByUserId,
      });
    }
  }

  return { allowed, ownSet, sharedMetaByGroupId };
}

async function buildAllowedVoiceContext(userId, workspaceId) {
  const ownIds = await heygenDao.listVoiceIdsForUser(userId);
  const ownSet = new Set(ownIds);
  const allowed = new Set(ownIds);
  const sharedMetaByVoiceId = new Map();

  const normalizedWorkspaceId = normalizeWorkspaceId(workspaceId);
  if (!normalizedWorkspaceId) {
    return { allowed, ownSet, sharedMetaByVoiceId };
  }

  await assertWorkspaceMember(userId, normalizedWorkspaceId);
  const sharedRows = await heygenShareDao.listSharedVoiceIdsForWorkspace(normalizedWorkspaceId);
  for (const row of sharedRows) {
    if (!row.voiceId) continue;
    allowed.add(row.voiceId);
    if (!ownSet.has(row.voiceId)) {
      sharedMetaByVoiceId.set(row.voiceId, {
        shared: true,
        sharedByUserId: row.sharedByUserId,
      });
    }
  }

  return { allowed, ownSet, sharedMetaByVoiceId };
}

async function resolveAvatarGroupIdFromLook(lookOrGroupId) {
  const id = String(lookOrGroupId || '').trim();
  if (!id) return null;

  const registered = await prisma.heygenAvatar.findFirst({
    where: { avatarGroupId: id },
    select: { avatarGroupId: true },
  });
  if (registered) return id;

  try {
    const single = await getJson(`/v3/avatars/looks/${encodeURIComponent(id)}`);
    const data = single && typeof single === 'object' && 'data' in single ? single.data : single;
    const look = data && typeof data === 'object' && !Array.isArray(data) ? data : null;
    const groupId =
      look?.avatar_group_id ??
      look?.group_id ??
      look?.avatar_group?.id ??
      look?.avatar_group?.avatar_group_id ??
      null;
    return groupId != null ? String(groupId).trim() : id;
  } catch {
    return id;
  }
}

async function resolveAccessibleAvatarGroupId(userId, workspaceId, groupOrLookId) {
  const { allowed } = await buildAllowedAvatarGroupContext(userId, workspaceId);
  const trimmed = String(groupOrLookId || '').trim();
  if (!trimmed) return null;

  const resolved = await resolveAvatarGroupIdFromLook(trimmed);
  if (resolved && allowed.has(resolved)) return resolved;
  if (allowed.has(trimmed)) return trimmed;

  if (await heygenDao.userOwnsAvatarGroup(userId, trimmed)) return trimmed;

  try {
    const single = await getJson(`/v3/avatars/looks/${encodeURIComponent(trimmed)}`);
    const data = single && typeof single === 'object' && 'data' in single ? single.data : single;
    const look = data && typeof data === 'object' && !Array.isArray(data) ? data : null;
    const groupId =
      look?.avatar_group_id ??
      look?.group_id ??
      look?.avatar_group?.id ??
      look?.avatar_group?.avatar_group_id ??
      null;
    if (groupId && allowed.has(String(groupId))) return String(groupId);
  } catch {
    // ignore
  }

  return null;
}

async function assertCanUseAvatarLook({ userId, workspaceId, avatarId }) {
  const groupId = await resolveAvatarGroupIdFromLook(avatarId);
  if (!groupId) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  if (await heygenDao.userOwnsAvatarGroup(userId, groupId)) {
    return groupId;
  }

  const normalizedWorkspaceId = normalizeWorkspaceId(workspaceId);
  if (
    normalizedWorkspaceId &&
    (await heygenShareDao.isAvatarGroupSharedToWorkspace(normalizedWorkspaceId, groupId))
  ) {
    return groupId;
  }

  const isRegistered = await heygenShareDao.isAvatarGroupRegisteredPrivate(groupId);
  if (!isRegistered) {
    return groupId;
  }

  throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
}

async function assertCanUseVoice({ userId, workspaceId, voiceId }) {
  const normalizedVoiceId = String(voiceId || '').trim();
  if (!normalizedVoiceId) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  if (await heygenDao.userOwnsVoice(userId, normalizedVoiceId)) {
    return normalizedVoiceId;
  }

  const normalizedWorkspaceId = normalizeWorkspaceId(workspaceId);
  if (
    normalizedWorkspaceId &&
    (await heygenShareDao.isVoiceSharedToWorkspace(normalizedWorkspaceId, normalizedVoiceId))
  ) {
    return normalizedVoiceId;
  }

  if (await heygenDao.cloneVoiceOwnedByOtherUser(userId, normalizedVoiceId)) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  const voiceRow = await heygenShareDao.findVoiceOwnerUserId(normalizedVoiceId);
  if (voiceRow && voiceRow.source === 'clone' && voiceRow.userId !== userId) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }

  return normalizedVoiceId;
}

module.exports = {
  normalizeWorkspaceId,
  assertWorkspaceMember,
  buildAllowedAvatarGroupContext,
  buildAllowedVoiceContext,
  resolveAvatarGroupIdFromLook,
  resolveAccessibleAvatarGroupId,
  assertCanUseAvatarLook,
  assertCanUseVoice,
};
