const { redisClient } = require('../../shared/config/redis');

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

const onlineKey = (shareId) => `ppt:share:${shareId}:online`;
const viewerKeyOf = (shareId, viewerKey) => `ppt:share:${shareId}:v:${viewerKey}`;

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

async function pruneStale(shareId) {
  const cutoff = Date.now() - VIEWER_TTL_SEC * 1000;
  try {
    await redisClient.zRemRangeByScore(onlineKey(shareId), 0, cutoff);
  } catch {
    // presence is best-effort; never fail the request over it
  }
}

/**
 * @param {string} shareId
 * @returns {Promise<{ viewerCount: number, viewers: object[] }>}
 */
async function listViewers(shareId) {
  await pruneStale(shareId);

  const key = onlineKey(shareId);
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
      redisClient.get(viewerKeyOf(shareId, entry.value)).catch(() => null)
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

/**
 * Record a heartbeat. Per-viewer payload keys self-expire, so no SCAN is ever needed.
 * @param {{ shareId: string, viewerKey: string, identity: object, slideIndex?: number }} params
 */
async function heartbeat({ shareId, viewerKey, identity, slideIndex = 0 }) {
  const now = Date.now();
  const payload = JSON.stringify({
    displayName: identity.displayName,
    isAnonymous: identity.isAnonymous,
    slideIndex: Number.isFinite(slideIndex) ? slideIndex : 0,
    lastSeen: new Date(now).toISOString(),
  });

  try {
    await Promise.all([
      redisClient.zAdd(onlineKey(shareId), { score: now, value: viewerKey }),
      redisClient.set(viewerKeyOf(shareId, viewerKey), payload, { EX: VIEWER_TTL_SEC }),
    ]);
    // Safety net so an abandoned share cannot keep a zset alive forever.
    await redisClient.expire(onlineKey(shareId), VIEWER_TTL_SEC * 10);
  } catch {
    // best-effort
  }
}

async function leave({ shareId, viewerKey }) {
  try {
    await Promise.all([
      redisClient.zRem(onlineKey(shareId), viewerKey),
      redisClient.del(viewerKeyOf(shareId, viewerKey)),
    ]);
  } catch {
    // best-effort; TTL covers missed calls
  }
}

/** Drop the whole room (disable, rotate, presentation delete). Reads members instead of SCAN. */
async function clearRoom(shareId) {
  if (!shareId) return;
  const key = onlineKey(shareId);
  try {
    const entries = await redisClient.zRangeWithScores(key, 0, -1);
    const keys = entries.map((entry) => viewerKeyOf(shareId, entry.value));
    if (keys.length > 0) {
      await redisClient.del(keys);
    }
    await redisClient.del(key);
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
  heartbeat,
  leave,
  clearRoom,
};
