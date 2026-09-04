const prisma = require('../../shared/config/prismaClient');
const presentationDao = require('../presentation/presentation.dao');

/**
 * Safe for Redis meta cache / public resolve. Never includes the raw capability token.
 */
const shareSelect = {
  id: true,
  projectId: true,
  workspaceId: true,
  tokenPrefix: true,
  role: true,
  enabled: true,
  createdBy: true,
  revokedAt: true,
  rotateCount: true,
  createdAt: true,
  updatedAt: true,
};

/** Owner APIs only — includes raw token so the FE can redisplay a copyable URL. */
const ownerShareSelect = {
  ...shareSelect,
  token: true,
};

const listSharesByProjectId = (projectId) => {
  return prisma.presentationShareLink.findMany({
    where: { projectId },
    select: ownerShareSelect,
    orderBy: { role: 'asc' },
  });
};

const findShareByProjectAndRole = (projectId, role) => {
  return prisma.presentationShareLink.findUnique({
    where: { projectId_role: { projectId, role } },
    select: ownerShareSelect,
  });
};

/** Resolve a capability token. Returns the row regardless of enabled; callers gate. */
const findShareByTokenHash = (tokenHash) => {
  return prisma.presentationShareLink.findUnique({
    where: { tokenHash },
    select: shareSelect,
  });
};

/**
 * Ownership guard for the owner-side share routes. Deliberately avoids loadPresentationDeck:
 * share metadata does not need the slide JSON blobs, which can be megabytes per deck.
 */
const findPresentationForShare = (projectId) => {
  return prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true,
      name: true,
      workspaceId: true,
      type: true,
      deck: { select: { id: true, status: true } },
    },
  });
};

/** Server-only lookup that exposes tokenHash so callers can invalidate the Redis meta cache. */
const findShareInternalByProjectAndRole = (projectId, role) => {
  return prisma.presentationShareLink.findUnique({
    where: { projectId_role: { projectId, role } },
    select: { ...ownerShareSelect, tokenHash: true },
  });
};

const listSharesInternalByProjectId = (projectId) => {
  return prisma.presentationShareLink.findMany({
    where: { projectId },
    select: { id: true, tokenHash: true, role: true },
  });
};

/**
 * Light version probe for the presence hot path: avoids loading every slide blob.
 * @param {string} projectId
 */
/** Shared with the member preview so both paths version a deck identically. */
const getContentVersion = (projectId) => presentationDao.findDeckContentVersion(projectId);

const createShare = (data) => {
  return prisma.presentationShareLink.create({
    data,
    select: ownerShareSelect,
  });
};

const updateShareById = (id, data) => {
  return prisma.presentationShareLink.update({
    where: { id },
    data,
    select: ownerShareSelect,
  });
};

/** Only the display name: the auth session carries a userId, and email never goes public. */
const findViewerName = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { name: true },
  });
  return user ? user.name : null;
};

const createAudit = (data) => {
  return prisma.presentationShareAudit.create({ data });
};

/**
 * Rotate inside a transaction so the audit row and the new hash land together.
 * @param {{ id: string, token: string, tokenHash: string, tokenPrefix: string, actorUserId?: string|null, ip?: string|null }} params
 */
const rotateShareToken = ({ id, token, tokenHash, tokenPrefix, actorUserId = null, ip = null }) => {
  return prisma.$transaction(async (tx) => {
    const share = await tx.presentationShareLink.update({
      where: { id },
      data: {
        token,
        tokenHash,
        tokenPrefix,
        enabled: true,
        revokedAt: null,
        rotateCount: { increment: 1 },
      },
      select: ownerShareSelect,
    });

    await tx.presentationShareAudit.create({
      data: { shareId: id, actorUserId, action: 'ROTATED', ip },
    });

    return share;
  });
};

module.exports = {
  shareSelect,
  ownerShareSelect,
  findPresentationForShare,
  listSharesByProjectId,
  findShareByProjectAndRole,
  findShareInternalByProjectAndRole,
  listSharesInternalByProjectId,
  findShareByTokenHash,
  getContentVersion,
  findViewerName,
  createShare,
  updateShareById,
  createAudit,
  rotateShareToken,
};
