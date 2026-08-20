const prisma = require('../../shared/config/prismaClient');

const shareSelect = {
  id: true,
  projectId: true,
  workspaceId: true,
  tokenPrefix: true,
  access: true,
  enabled: true,
  expiresAt: true,
  createdBy: true,
  revokedAt: true,
  rotateCount: true,
  createdAt: true,
  updatedAt: true,
};

const findShareByProjectId = (projectId) => {
  return prisma.presentationShareLink.findUnique({
    where: { projectId },
    select: shareSelect,
  });
};

/** Resolve a capability token. Returns the row regardless of enabled/expiry; callers gate. */
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
const findShareInternalByProjectId = (projectId) => {
  return prisma.presentationShareLink.findUnique({
    where: { projectId },
    select: { ...shareSelect, tokenHash: true },
  });
};

/**
 * Light version probe for the presence hot path: avoids loading every slide blob.
 * @param {string} projectId
 */
const getContentVersion = async (projectId) => {
  const deck = await prisma.deck.findUnique({
    where: { projectId },
    select: { id: true, updatedAt: true },
  });
  if (!deck) return null;

  const aggregate = await prisma.slide.aggregate({
    where: { deckId: deck.id, status: 'READY' },
    _max: { updatedAt: true },
    _count: { _all: true },
  });

  return {
    deckUpdatedAt: deck.updatedAt,
    slideUpdatedAt: aggregate._max.updatedAt,
    readySlideCount: aggregate._count._all,
  };
};

const createShare = (data) => {
  return prisma.presentationShareLink.create({
    data,
    select: shareSelect,
  });
};

const updateShareById = (id, data) => {
  return prisma.presentationShareLink.update({
    where: { id },
    data,
    select: shareSelect,
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
 * @param {{ id: string, tokenHash: string, tokenPrefix: string, actorUserId?: string|null, ip?: string|null }} params
 */
const rotateShareToken = ({ id, tokenHash, tokenPrefix, actorUserId = null, ip = null }) => {
  return prisma.$transaction(async (tx) => {
    const share = await tx.presentationShareLink.update({
      where: { id },
      data: {
        tokenHash,
        tokenPrefix,
        enabled: true,
        revokedAt: null,
        rotateCount: { increment: 1 },
      },
      select: shareSelect,
    });

    await tx.presentationShareAudit.create({
      data: { shareId: id, actorUserId, action: 'ROTATED', ip },
    });

    return share;
  });
};

module.exports = {
  shareSelect,
  findPresentationForShare,
  findShareByProjectId,
  findShareInternalByProjectId,
  findShareByTokenHash,
  getContentVersion,
  findViewerName,
  createShare,
  updateShareById,
  createAudit,
  rotateShareToken,
};
