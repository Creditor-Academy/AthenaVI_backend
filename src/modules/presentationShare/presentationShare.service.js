const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { redisClient } = require('../../shared/config/redis');
const deckGeneration = require('../presentation/deckGeneration.service');
const { enrichSlidesForClient } = require('../presentation/elementContent.normalize');
const workspaceDao = require('../workspace/workspace.dao');
const shareDao = require('./presentationShare.dao');
const presence = require('./presentationShare.presence');
const { presignSlidesForPublic, buildContentVersion } = require('./presentationShare.presign');

const TOKEN_BYTES = 32;
const TOKEN_PREFIX_LENGTH = 8;

const META_TTL_SEC =
  Number(process.env.PPT_SHARE_META_CACHE_TTL_SEC) > 0
    ? Number(process.env.PPT_SHARE_META_CACHE_TTL_SEC)
    : 60;

const CONTENT_VERSION_TTL_SEC =
  Number(process.env.PPT_SHARE_CONTENT_VERSION_TTL_SEC) > 0
    ? Number(process.env.PPT_SHARE_CONTENT_VERSION_TTL_SEC)
    : 10;

const VIEWER_NAME_TTL_SEC =
  Number(process.env.PPT_SHARE_VIEWER_NAME_TTL_SEC) > 0
    ? Number(process.env.PPT_SHARE_VIEWER_NAME_TTL_SEC)
    : 300;

const metaKey = (tokenHash) => `ppt:share:meta:${tokenHash}`;
const contentVersionKey = (projectId) => `ppt:share:cv:${projectId}`;
const viewerNameKey = (userId) => `ppt:share:name:${userId}`;

const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex');

function mintToken() {
  const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  return {
    token,
    tokenHash: hashToken(token),
    tokenPrefix: token.slice(0, TOKEN_PREFIX_LENGTH),
  };
}

function frontendBase() {
  return String(process.env.FRONTEND_URL || '').replace(/\/$/, '');
}

const buildShareUrl = (token) => `${frontendBase()}/p/${token}`;

const isExpired = (share) =>
  Boolean(share?.expiresAt) && new Date(share.expiresAt).getTime() <= Date.now();

function shareNotFound() {
  return new AppError(messages.PRESENTATION_SHARE_NOT_FOUND, 404);
}

function toOwnerShare(share) {
  if (!share) {
    return { enabled: false, exists: false };
  }

  const out = {
    exists: true,
    enabled: share.enabled,
    expired: isExpired(share),
    access: share.access,
    expiresAt: share.expiresAt,
    rotateCount: share.rotateCount,
    createdBy: share.createdBy,
    createdAt: share.createdAt,
    updatedAt: share.updatedAt,
  };

  // Legacy rows created before token persistence have no recoverable URL — FE should rotate.
  if (share.token) {
    out.token = share.token;
    out.url = buildShareUrl(share.token);
  }

  return out;
}

async function invalidateMeta(tokenHash) {
  if (!tokenHash) return;
  try {
    await redisClient.del(metaKey(tokenHash));
  } catch {
    // cache invalidation is best-effort; TTL bounds the staleness
  }
}

/**
 * The auth session only carries a userId, so the display name comes from Postgres. Cached
 * briefly because the presence heartbeat is a hot path; a renamed user lags by the TTL.
 * @param {{ id?: string }|null} user
 */
async function loadViewerIdentity(user) {
  if (!user?.id) {
    return presence.resolveViewerIdentity(null);
  }

  const key = viewerNameKey(user.id);
  try {
    const cached = await redisClient.get(key);
    if (cached !== null) {
      return presence.resolveViewerIdentity({ id: user.id, name: cached });
    }
  } catch {
    // fall through to Postgres
  }

  let name = null;
  try {
    name = await shareDao.findViewerName(user.id);
  } catch {
    name = null;
  }

  try {
    await redisClient.set(key, name || '', { EX: VIEWER_NAME_TTL_SEC });
  } catch {
    // best-effort
  }

  return presence.resolveViewerIdentity({ id: user.id, name });
}

/**
 * Owner-side guard: the presentation must exist, be a deck, and live in this workspace.
 * A mismatch 404s rather than 403s so the route cannot confirm foreign presentation ids.
 */
async function loadOwnerContext(workspaceId, presentationId) {
  const project = await shareDao.findPresentationForShare(presentationId);

  if (
    !project ||
    project.type !== 'PRESENTATION' ||
    project.workspaceId !== workspaceId ||
    !project.deck
  ) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  return { deck: project.deck, project };
}

function assertNotGenerating(deck) {
  if (deck?.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }
}

/* =========================
   Owner APIs
========================= */

async function enableShare({ workspaceId, presentationId, userId, ip }) {
  const { deck } = await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectId(presentationId);

  if (!existing) {
    assertNotGenerating(deck);
    const { token, tokenHash, tokenPrefix } = mintToken();

    let created;
    try {
      created = await shareDao.createShare({
        projectId: presentationId,
        workspaceId,
        token,
        tokenHash,
        tokenPrefix,
        createdBy: userId || null,
      });
    } catch (err) {
      // Concurrent first-enable: projectId is unique, so the loser reports the winner's link.
      if (err?.code === 'P2002') {
        const winner = await shareDao.findShareByProjectId(presentationId);
        if (winner) return { share: toOwnerShare(winner) };
      }
      throw err;
    }

    await shareDao.createAudit({
      shareId: created.id,
      actorUserId: userId || null,
      action: 'CREATED',
      ip: ip || null,
    });

    return { share: toOwnerShare(created), token, url: buildShareUrl(token) };
  }

  const expired = isExpired(existing);
  if (existing.enabled && !expired) {
    return { share: toOwnerShare(existing) };
  }

  assertNotGenerating(deck);
  const updated = await shareDao.updateShareById(existing.id, {
    enabled: true,
    revokedAt: null,
    ...(expired ? { expiresAt: null } : {}),
  });
  await shareDao.createAudit({
    shareId: existing.id,
    actorUserId: userId || null,
    action: 'ENABLED',
    ip: ip || null,
  });
  await invalidateMeta(existing.tokenHash);

  return { share: toOwnerShare(updated) };
}

async function getShare({ workspaceId, presentationId }) {
  await loadOwnerContext(workspaceId, presentationId);
  const share = await shareDao.findShareByProjectId(presentationId);
  return { share: toOwnerShare(share) };
}

async function updateShare({ workspaceId, presentationId, userId, ip, enabled, expiresAt }) {
  const { deck } = await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectId(presentationId);
  if (!existing) {
    throw shareNotFound();
  }

  const data = {};
  let action = null;

  if (enabled === true && !existing.enabled) {
    assertNotGenerating(deck);
    data.enabled = true;
    data.revokedAt = null;
    action = 'ENABLED';
  }

  if (enabled === false && existing.enabled) {
    data.enabled = false;
    data.revokedAt = new Date();
    action = 'DISABLED';
  }

  if (expiresAt !== undefined) {
    data.expiresAt = expiresAt === null ? null : new Date(expiresAt);
  }

  const updated = Object.keys(data).length > 0
    ? await shareDao.updateShareById(existing.id, data)
    : existing;

  if (action) {
    await shareDao.createAudit({
      shareId: existing.id,
      actorUserId: userId || null,
      action,
      ip: ip || null,
    });
  }

  await invalidateMeta(existing.tokenHash);
  if (data.enabled === false) {
    await presence.clearRoom(existing.id);
  }

  return { share: toOwnerShare(updated) };
}

async function rotateShare({ workspaceId, presentationId, userId, ip }) {
  await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectId(presentationId);
  if (!existing) {
    throw shareNotFound();
  }

  let minted = mintToken();
  let rotated;
  try {
    rotated = await shareDao.rotateShareToken({
      id: existing.id,
      token: minted.token,
      tokenHash: minted.tokenHash,
      tokenPrefix: minted.tokenPrefix,
      actorUserId: userId || null,
      ip: ip || null,
    });
  } catch (err) {
    // tokenHash is globally unique; a collision is implausible but retry once rather than 500.
    if (err?.code !== 'P2002') throw err;
    minted = mintToken();
    rotated = await shareDao.rotateShareToken({
      id: existing.id,
      token: minted.token,
      tokenHash: minted.tokenHash,
      tokenPrefix: minted.tokenPrefix,
      actorUserId: userId || null,
      ip: ip || null,
    });
  }
  const token = minted.token;

  await invalidateMeta(existing.tokenHash);
  await presence.clearRoom(existing.id);

  return { share: toOwnerShare(rotated), token, url: buildShareUrl(token) };
}

/** Called before a presentation row is deleted so no Redis room outlives the link. */
async function invalidateForProject(projectId) {
  try {
    const existing = await shareDao.findShareInternalByProjectId(projectId);
    if (!existing) return;
    await invalidateMeta(existing.tokenHash);
    await presence.clearRoom(existing.id);
    await redisClient.del(contentVersionKey(projectId));
  } catch {
    // never block a delete on cache cleanup
  }
}

/* =========================
   Public capability-token APIs
========================= */

/**
 * Resolve a raw token to a usable share. Disabled, expired, and unknown tokens all raise the
 * same 404 so the endpoint cannot be used to enumerate presentations.
 */
async function resolveShare(token) {
  const tokenHash = hashToken(token);
  let cached = null;

  try {
    cached = await redisClient.get(metaKey(tokenHash));
  } catch {
    cached = null;
  }

  if (cached === 'null') {
    throw shareNotFound();
  }

  let share = null;
  if (cached) {
    try {
      share = JSON.parse(cached);
    } catch {
      share = null;
    }
  }

  if (!share) {
    share = await shareDao.findShareByTokenHash(tokenHash);
    try {
      await redisClient.set(metaKey(tokenHash), share ? JSON.stringify(share) : 'null', {
        EX: share ? META_TTL_SEC : Math.min(META_TTL_SEC, 30),
      });
    } catch {
      // cache write is best-effort
    }
  }

  if (!share || !share.enabled || isExpired(share)) {
    throw shareNotFound();
  }

  return { share, tokenHash };
}

/** Strip internal storage pointers from element content before it leaves the server. */
function sanitizeElementsDoc(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.elements)) {
    return doc || null;
  }

  return {
    ...doc,
    elements: doc.elements.map((el) => {
      if (!el || !el.content || typeof el.content !== 'object') return el;
      const { s3Key, assetId, ...content } = el.content;
      void s3Key;
      void assetId;
      return { ...el, content };
    }),
  };
}

function toPublicSlide(slide) {
  return {
    id: slide.id,
    order: slide.order,
    status: slide.status,
    ...(slide.title != null ? { title: slide.title } : {}),
    ...(slide.description != null ? { description: slide.description } : {}),
    elements: sanitizeElementsDoc(slide.elements),
  };
}

/**
 * View-only deck payload. Editor-only fields (outline, generation metrics, credits, folder,
 * workspace, owner) never appear here, and only READY slides are exposed so a regeneration
 * in flight cannot show half-built frames.
 */
async function getPublicPresentation(token) {
  const { share } = await resolveShare(token);

  let deck;
  let project;
  try {
    ({ deck, project } = await deckGeneration.loadPresentationDeck(share.projectId));
  } catch {
    throw shareNotFound();
  }

  const readySlides = (deck.slides || []).filter((slide) => slide.status === 'READY');
  const version = buildContentVersion({ deck, slides: readySlides, share });

  const presigned = await presignSlidesForPublic(readySlides);
  const slides = enrichSlidesForClient(presigned).map(toPublicSlide);

  return {
    etag: version.etag,
    data: {
      id: project.id,
      title: project.name,
      permission: 'view',
      status: deck.status,
      aspectRatio: deck.aspectRatio,
      locale: deck.locale,
      themeTokens: deck.themeTokens,
      contentUpdatedAt: version.contentUpdatedAt,
      slideCount: slides.length,
      slides,
    },
  };
}

async function getContentUpdatedAt(projectId) {
  const key = contentVersionKey(projectId);
  try {
    const cached = await redisClient.get(key);
    if (cached) return cached === 'null' ? null : cached;
  } catch {
    // fall through to a fresh read
  }

  const probe = await shareDao.getContentVersion(projectId);
  const version = buildContentVersion({
    deck: probe ? { updatedAt: probe.deckUpdatedAt } : null,
    slides: probe?.slideUpdatedAt ? [{ updatedAt: probe.slideUpdatedAt }] : [],
    share: null,
  });

  try {
    await redisClient.set(key, version.contentUpdatedAt || 'null', {
      EX: CONTENT_VERSION_TTL_SEC,
    });
  } catch {
    // best-effort
  }

  return version.contentUpdatedAt;
}

/**
 * Personalized companion to the cacheable deck payload. Kept separate so the deck response
 * stays identical for every viewer and can be cached / ETag-matched.
 */
async function getPublicSession({ token, user }) {
  const { share } = await resolveShare(token);
  const identity = await loadViewerIdentity(user);

  let canOpenInEditor = false;
  if (user?.id) {
    const membership = await workspaceDao.findWorkspaceMember(share.workspaceId, user.id);
    canOpenInEditor = Boolean(membership);
  }

  return {
    self: {
      displayName: identity.displayName,
      isAnonymous: identity.isAnonymous,
      ...(identity.userId ? { userId: identity.userId } : {}),
    },
    permission: 'view',
    canOpenInEditor,
    ...(canOpenInEditor
      ? { workspaceId: share.workspaceId, presentationId: share.projectId }
      : {}),
  };
}

async function buildPresencePayload({ share, user, identity }) {
  const resolved = identity || (await loadViewerIdentity(user));
  const [{ viewerCount, viewers }, contentUpdatedAt] = await Promise.all([
    presence.listViewers(share.id),
    getContentUpdatedAt(share.projectId),
  ]);

  return {
    self: { displayName: resolved.displayName, isAnonymous: resolved.isAnonymous },
    viewerCount,
    viewers,
    contentUpdatedAt,
  };
}

async function heartbeatPresence({ token, user, viewerSessionId, slideIndex }) {
  const { share } = await resolveShare(token);
  const identity = await loadViewerIdentity(user);
  const viewerKey = presence.buildViewerKey({ user, viewerSessionId });

  await presence.heartbeat({ shareId: share.id, viewerKey, identity, slideIndex });

  return buildPresencePayload({ share, user, identity });
}

async function listPresence({ token, user }) {
  const { share } = await resolveShare(token);
  return buildPresencePayload({ share, user });
}

async function leavePresence({ token, user, viewerSessionId }) {
  const { share } = await resolveShare(token);
  const viewerKey = presence.buildViewerKey({ user, viewerSessionId });
  await presence.leave({ shareId: share.id, viewerKey });
  return { left: true };
}

module.exports = {
  hashToken,
  buildShareUrl,
  enableShare,
  getShare,
  updateShare,
  rotateShare,
  invalidateForProject,
  getPublicPresentation,
  getPublicSession,
  heartbeatPresence,
  listPresence,
  leavePresence,
};
