/**
 * Redis presence for share-link viewers and the member Present cursor.
 *
 * Viewer zset (`ppt:share:{projectId}:online`) is unchanged. Presenter lock
 * (`ppt:present:{projectId}`) is first-writer-wins with TTL = VIEWER_TTL_SEC.
 */

const crypto = require('crypto');
const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const ANONYMOUS_LABEL = 'Anonymous viewer';

const VIEWER_TTL_SEC =
  Number(process.env.PPT_SHARE_PRESENCE_TTL_SEC) > 0
    ? Number(process.env.PPT_SHARE_PRESENCE_TTL_SEC)
    : 45;

/** Most-recently-active viewers returned per request. Display cap only: nobody is rejected. */
const VIEWER_DISPLAY_LIMIT =
  Number(process.env.PPT_SHARE_PRESENCE_DISPLAY_LIMIT) > 0
    ? Number(process.env.PPT_SHARE_PRESENCE_DISPLAY_LIMIT)
    : 50;

const onlineKey = (projectId) => `ppt:share:${projectId}:online`;
const viewerKeyOf = (projectId, viewerKey) => `ppt:share:${projectId}:v:${viewerKey}`;
const presenterKey = (projectId) => `ppt:present:${projectId}`;

/**
 * Server-computed label. A client-supplied name is never trusted, and email is never exposed
 * on a public channel. `User.name` is nullable, so a blank name falls back to anonymous.
 * @param {{ id?: string, name?: string|null }|null} user
 */
function resolveViewerIdentity(user) {
  const trimmed = user?.name != null ? String(user.name).trim() : '';
  if (user?.id && trimmed) {
    return { userId: user.id, displayName: trimmed, isAnonymous: false };
  }
  return { userId: user?.id || null, displayName: ANONYMOUS_LABEL, isAnonymous: true };
}

/** Logged-in viewers collapse across tabs; guests are keyed by their client session id. */
function buildViewerKey({ user, viewerSessionId }) {
  if (user?.id) return `user:${user.id}`;
  return `anon:${viewerSessionId}`;
}

function mintLeaveToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashLeaveToken(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

function toPublicPresenter(lock) {
  if (!lock) return null;
  return {
    slideIndex: Number.isFinite(Number(lock.slideIndex)) ? Number(lock.slideIndex) : 0,
    displayName: lock.displayName || ANONYMOUS_LABEL,
    seq: Number(lock.seq) || 0,
    updatedAt: lock.updatedAt || null,
  };
}

function conflictError(lock) {
  const message = messages.PRESENTATION_ALREADY_PRESENTING;
  const err = new AppError(message, 409);
  err.errors = [
    {
      message,
      presentingUserId: lock.userId,
      displayName: lock.displayName || ANONYMOUS_LABEL,
    },
  ];
  return err;
}

async function pruneStale(projectId) {
  const cutoff = Date.now() - VIEWER_TTL_SEC * 1000;
  try {
    await redisClient.zRemRangeByScore(onlineKey(projectId), 0, cutoff);
  } catch {
    // presence is best-effort; never fail the request over it
  }
}

/**
 * @param {string} projectId
 * @returns {Promise<{ viewerCount: number, viewers: object[] }>}
 */
async function listViewers(projectId) {
  await pruneStale(projectId);

  const key = onlineKey(projectId);
  let entries = [];
  let viewerCount = 0;

  try {
    viewerCount = await redisClient.zCard(key);
    // Negative indexes take the highest-scored (most recent) members; reversed below.
    entries = await redisClient.zRangeWithScores(key, -VIEWER_DISPLAY_LIMIT, -1);
  } catch {
    return { viewerCount: 0, viewers: [] };
  }

  const recent = [...entries].reverse();
  if (recent.length === 0) {
    return { viewerCount, viewers: [] };
  }

  // node-redis pipelines commands issued in the same tick, so this is one round trip.
  const payloads = await Promise.all(
    recent.map((entry) =>
      redisClient.get(viewerKeyOf(projectId, entry.value)).catch(() => null)
    )
  );

  const viewers = [];
  payloads.forEach((raw, index) => {
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw);
      viewers.push({
        key: recent[index].value,
        displayName: parsed.displayName || ANONYMOUS_LABEL,
        isAnonymous: parsed.isAnonymous !== false,
        slideIndex: Number.isFinite(parsed.slideIndex) ? parsed.slideIndex : 0,
        lastSeen: parsed.lastSeen || null,
      });
    } catch {
      // skip unreadable payloads
    }
  });

  return { viewerCount, viewers };
}

async function readPresenterLock(projectId) {
  try {
    const raw = await redisClient.get(presenterKey(projectId));
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Public follow cursor — never includes userId or leaveToken. */
async function getPublicPresenter(projectId) {
  return toPublicPresenter(await readPresenterLock(projectId));
}

/**
 * Acquire / heartbeat / release the presenter lock.
 * Raw leaveToken is returned only on NX acquire (never reminted on later heartbeats).
 *
 * @returns {Promise<{ presenter: object|null, leaveToken: string|null, acquired: boolean,
 *   released: boolean, startedAt: string|null }>}
 */
async function acquireOrRefreshPresenter({
  projectId,
  userId,
  displayName,
  slideIndex = 0,
  presenting = false,
}) {
  const key = presenterKey(projectId);
  const clampedIndex = Number.isFinite(Number(slideIndex)) ? Number(slideIndex) : 0;

  if (!presenting) {
    const existing = await readPresenterLock(projectId);
    if (existing?.userId === userId) {
      try {
        await redisClient.del(key);
      } catch {
        // best-effort; TTL covers
      }
      return {
        presenter: null,
        leaveToken: null,
        acquired: false,
        released: true,
        startedAt: existing.startedAt || null,
      };
    }
    return {
      presenter: toPublicPresenter(existing),
      leaveToken: null,
      acquired: false,
      released: false,
      startedAt: null,
    };
  }

  let existing = await readPresenterLock(projectId);

  if (!existing) {
    const leaveToken = mintLeaveToken();
    const now = new Date().toISOString();
    const payload = {
      userId,
      displayName: displayName || ANONYMOUS_LABEL,
      slideIndex: clampedIndex,
      seq: 1,
      leaveTokenHash: hashLeaveToken(leaveToken),
      startedAt: now,
      updatedAt: now,
    };

    let acquired = false;
    try {
      acquired = (await redisClient.set(key, JSON.stringify(payload), {
        NX: true,
        EX: VIEWER_TTL_SEC,
      })) === 'OK';
    } catch {
      acquired = false;
    }

    if (acquired) {
      return {
        presenter: toPublicPresenter(payload),
        leaveToken,
        acquired: true,
        released: false,
        startedAt: now,
      };
    }

    existing = await readPresenterLock(projectId);
  }

  if (!existing) {
    // Race lost and lock vanished — treat as conflict-free miss; caller may retry.
    throw new AppError(messages.PRESENTATION_ALREADY_PRESENTING, 409);
  }

  if (existing.userId !== userId) {
    throw conflictError(existing);
  }

  const now = new Date().toISOString();
  const next = {
    ...existing,
    displayName: displayName || existing.displayName || ANONYMOUS_LABEL,
    slideIndex: clampedIndex,
    seq: (Number(existing.seq) || 0) + 1,
    updatedAt: now,
  };

  try {
    await redisClient.set(key, JSON.stringify(next), { EX: VIEWER_TTL_SEC });
  } catch {
    // best-effort
  }

  return {
    presenter: toPublicPresenter(next),
    leaveToken: null,
    acquired: false,
    released: false,
    startedAt: existing.startedAt || null,
  };
}

/**
 * Release presenter lock when caller is the holder (userId match or leaveToken hash match).
 * @returns {Promise<{ released: boolean, userId: string|null, startedAt: string|null }>}
 */
async function leavePresenter(projectId, { userId = null, leaveToken = null } = {}) {
  const existing = await readPresenterLock(projectId);
  if (!existing) {
    return { released: false, userId: null, startedAt: null };
  }

  const tokenOk =
    leaveToken && existing.leaveTokenHash && hashLeaveToken(leaveToken) === existing.leaveTokenHash;
  const userOk = userId && existing.userId === userId;

  if (!tokenOk && !userOk) {
    return { released: false, userId: null, startedAt: null };
  }

  try {
    await redisClient.del(presenterKey(projectId));
  } catch {
    // best-effort
  }

  return {
    released: true,
    userId: existing.userId || null,
    startedAt: existing.startedAt || null,
  };
}

/**
 * Record a heartbeat. Per-viewer payload keys self-expire, so no SCAN is ever needed.
 * @param {{ projectId: string, viewerKey: string, identity: object, slideIndex?: number }} params
 */
async function heartbeat({ projectId, viewerKey, identity, slideIndex = 0 }) {
  const now = Date.now();
  const payload = JSON.stringify({
    displayName: identity.displayName,
    isAnonymous: identity.isAnonymous,
    slideIndex: Number.isFinite(slideIndex) ? slideIndex : 0,
    lastSeen: new Date(now).toISOString(),
  });

  try {
    await Promise.all([
      redisClient.zAdd(onlineKey(projectId), { score: now, value: viewerKey }),
      redisClient.set(viewerKeyOf(projectId, viewerKey), payload, { EX: VIEWER_TTL_SEC }),
    ]);
    // Safety net so an abandoned share cannot keep a zset alive forever.
    await redisClient.expire(onlineKey(projectId), VIEWER_TTL_SEC * 10);
  } catch {
    // best-effort
  }
}

async function leave({ projectId, viewerKey }) {
  try {
    await Promise.all([
      redisClient.zRem(onlineKey(projectId), viewerKey),
      redisClient.del(viewerKeyOf(projectId, viewerKey)),
    ]);
  } catch {
    // best-effort; TTL covers missed calls
  }
}

/** Drop the whole room (presentation delete). Reads members instead of SCAN. */
async function clearRoom(projectId) {
  if (!projectId) return;
  const key = onlineKey(projectId);
  try {
    const entries = await redisClient.zRangeWithScores(key, 0, -1);
    const keys = entries.map((entry) => viewerKeyOf(projectId, entry.value));
    if (keys.length > 0) {
      await redisClient.del(keys);
    }
    await redisClient.del([key, presenterKey(projectId)]);
  } catch {
    // best-effort
  }
}

module.exports = {
  ANONYMOUS_LABEL,
  VIEWER_TTL_SEC,
  VIEWER_DISPLAY_LIMIT,
  resolveViewerIdentity,
  buildViewerKey,
  listViewers,
  getPublicPresenter,
  acquireOrRefreshPresenter,
  leavePresenter,
  heartbeat,
  leave,
  clearRoom,
};
