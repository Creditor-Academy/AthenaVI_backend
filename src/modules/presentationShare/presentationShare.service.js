const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { redisClient } = require('../../shared/config/redis');
const deckGeneration = require('../presentation/deckGeneration.service');
const deckRender = require('../presentation/deckRender.service');
const workspaceDao = require('../workspace/workspace.dao');
const shareDao = require('./presentationShare.dao');
const presence = require('./presentationShare.presence');
const { getCommentsUpdatedAt } = require('../presentationComment/presentationComment.activity');
const { buildContentVersion } = require('./presentationShare.presign');

const TOKEN_BYTES = 32;
const TOKEN_PREFIX_LENGTH = 8;

const ROLE_VIEWER = 'VIEWER';
const ROLE_REVIEWER = 'REVIEWER';

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

function shareNotFound() {
  return new AppError(messages.PRESENTATION_SHARE_NOT_FOUND, 404);
}

function toOwnerLink(share) {
  if (!share) {
    return { exists: false };
  }

  const out = {
    exists: true,
    enabled: share.enabled,
    role: share.role,
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

function linkRoleFromShare(share) {
  return share.role === ROLE_REVIEWER ? 'reviewer' : 'viewer';
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

async function enableShareForRole({ workspaceId, presentationId, userId, ip, role }) {
  const { deck } = await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectAndRole(presentationId, role);

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
        role,
        createdBy: userId || null,
      });
    } catch (err) {
      // Concurrent first-enable: (projectId, role) is unique, so the loser reports the winner.
      if (err?.code === 'P2002') {
        const winner = await shareDao.findShareByProjectAndRole(presentationId, role);
        if (winner) return { link: toOwnerLink(winner) };
      }
      throw err;
    }

    await shareDao.createAudit({
      shareId: created.id,
      actorUserId: userId || null,
      action: 'CREATED',
      ip: ip || null,
    });

    return { link: toOwnerLink(created), token, url: buildShareUrl(token) };
  }

  if (existing.enabled) {
    return { link: toOwnerLink(existing) };
  }

  assertNotGenerating(deck);
  const updated = await shareDao.updateShareById(existing.id, {
    enabled: true,
    revokedAt: null,
  });
  await shareDao.createAudit({
    shareId: existing.id,
    actorUserId: userId || null,
    action: 'ENABLED',
    ip: ip || null,
  });
  await invalidateMeta(existing.tokenHash);

  return { link: toOwnerLink(updated) };
}

async function getShare({ workspaceId, presentationId }) {
  await loadOwnerContext(workspaceId, presentationId);
  const shares = await shareDao.listSharesByProjectId(presentationId);
  const byRole = Object.fromEntries(shares.map((row) => [row.role, row]));

  return {
    viewer: toOwnerLink(byRole[ROLE_VIEWER] || null),
    reviewer: toOwnerLink(byRole[ROLE_REVIEWER] || null),
  };
}

async function updateShareForRole({ workspaceId, presentationId, userId, ip, role, enabled }) {
  const { deck } = await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectAndRole(presentationId, role);
  if (!existing) {
    throw shareNotFound();
  }

  const data = {};
  const actions = [];

  if (enabled === true && !existing.enabled) {
    assertNotGenerating(deck);
    data.enabled = true;
    data.revokedAt = null;
    actions.push('ENABLED');
  }

  if (enabled === false && existing.enabled) {
    data.enabled = false;
    data.revokedAt = new Date();
    actions.push('DISABLED');
  }

  const updated =
    Object.keys(data).length > 0 ? await shareDao.updateShareById(existing.id, data) : existing;

  for (const auditAction of actions) {
    await shareDao.createAudit({
      shareId: existing.id,
      actorUserId: userId || null,
      action: auditAction,
      ip: ip || null,
    });
  }

  await invalidateMeta(existing.tokenHash);

  return { link: toOwnerLink(updated) };
}

async function rotateShareForRole({ workspaceId, presentationId, userId, ip, role }) {
  await loadOwnerContext(workspaceId, presentationId);
  const existing = await shareDao.findShareInternalByProjectAndRole(presentationId, role);
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

  return { link: toOwnerLink(rotated), token, url: buildShareUrl(token) };
}

/** Called before a presentation row is deleted so no Redis room outlives the links. */
async function invalidateForProject(projectId) {
  try {
    const shares = await shareDao.listSharesInternalByProjectId(projectId);
    for (const share of shares) {
      await invalidateMeta(share.tokenHash);
    }
    await presence.clearRoom(projectId);
    await redisClient.del(contentVersionKey(projectId));
  } catch {
    // never block a delete on cache cleanup
  }
}

/* =========================
   Public capability-token APIs
========================= */

/**
 * Resolve a raw token to a usable share. Disabled and unknown tokens all raise the same 404
 * so the endpoint cannot be used to enumerate presentations.
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

  if (!share || !share.enabled) {
    throw shareNotFound();
  }

  return { share, tokenHash };
}

/**
 * View-only deck payload. Editor-only fields (outline, generation metrics, credits, folder,
 * workspace, owner) never appear here, and only READY slides are exposed so a regeneration
 * in flight cannot show half-built frames.
 *
 * Shares its builder with the member preview so both render identically.
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

  const { etag, data } = await deckRender.buildDeckRenderPayload({
    project,
    deck,
    slides: readySlides,
    share,
    includeProgress: share.role === ROLE_REVIEWER,
    extra: { permission: 'view' },
  });

  return { etag, data };
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

  const canComment = share.role === ROLE_REVIEWER;
  const linkRole = linkRoleFromShare(share);

  return {
    self: {
      displayName: identity.displayName,
      isAnonymous: identity.isAnonymous,
      ...(identity.userId ? { userId: identity.userId } : {}),
    },
    linkRole,
    // Deck payload keeps `view` so its ETag stays identical for every viewer.
    permission: canComment ? 'review' : 'view',
    canComment,
    canResolveComments: canComment && canOpenInEditor,
    canOpenInEditor,
    ...(canOpenInEditor
      ? { workspaceId: share.workspaceId, presentationId: share.projectId }
      : {}),
  };
}

/**
 * Token + capability resolution for the public comment routes. Lives here so the comment
 * module never has to know how a share link is stored, and so the share service keeps its
 * single 404-for-everything policy on unknown and disabled links.
 *
 * @returns {Promise<{ share: object, canComment: boolean, canOpenInEditor: boolean, role: string|null }>}
 */
async function resolveShareForComments({ token, user }) {
  const { share } = await resolveShare(token);

  let membership = null;
  if (user?.id) {
    membership = await workspaceDao.findWorkspaceMember(share.workspaceId, user.id);
  }

  return {
    share,
    canComment: share.role === ROLE_REVIEWER,
    canOpenInEditor: Boolean(membership),
    role: membership?.role || null,
  };
}

async function buildPresencePayload({ share, user, identity }) {
  const resolved = identity || (await loadViewerIdentity(user));
  const [{ viewerCount, viewers }, contentUpdatedAt, commentsUpdatedAt] = await Promise.all([
    presence.listViewers(share.projectId),
    getContentUpdatedAt(share.projectId),
    getCommentsUpdatedAt(share.projectId),
  ]);

  return {
    self: { displayName: resolved.displayName, isAnonymous: resolved.isAnonymous },
    viewerCount,
    viewers,
    contentUpdatedAt,
    // Lets the viewer refetch comments off this same heartbeat instead of polling the list.
    commentsUpdatedAt,
  };
}

async function heartbeatPresence({ token, user, viewerSessionId, slideIndex }) {
  const { share } = await resolveShare(token);
  const identity = await loadViewerIdentity(user);
  const viewerKey = presence.buildViewerKey({ user, viewerSessionId });

  await presence.heartbeat({
    projectId: share.projectId,
    viewerKey,
    identity,
    slideIndex,
  });

  return buildPresencePayload({ share, user, identity });
}

async function listPresence({ token, user }) {
  const { share } = await resolveShare(token);
  return buildPresencePayload({ share, user });
}

async function leavePresence({ token, user, viewerSessionId }) {
  const { share } = await resolveShare(token);
  const viewerKey = presence.buildViewerKey({ user, viewerSessionId });
  await presence.leave({ projectId: share.projectId, viewerKey });
  return { left: true };
}

module.exports = {
  ROLE_VIEWER,
  ROLE_REVIEWER,
  hashToken,
  buildShareUrl,
  resolveShareForComments,
  enableShareForRole,
  getShare,
  updateShareForRole,
  rotateShareForRole,
  invalidateForProject,
  getPublicPresentation,
  getPublicSession,
  heartbeatPresence,
  listPresence,
  leavePresence,
};
