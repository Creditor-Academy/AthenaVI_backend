const crypto = require('crypto');
const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const WINDOW_SEC =
  Number(process.env.PPT_SHARE_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.PPT_SHARE_RATE_LIMIT_WINDOW_SEC)
    : 60;

const VIEW_IP_MAX =
  Number(process.env.PPT_SHARE_VIEW_RATE_LIMIT_IP) > 0
    ? Number(process.env.PPT_SHARE_VIEW_RATE_LIMIT_IP)
    : 60;

const VIEW_TOKEN_MAX =
  Number(process.env.PPT_SHARE_VIEW_RATE_LIMIT_TOKEN) > 0
    ? Number(process.env.PPT_SHARE_VIEW_RATE_LIMIT_TOKEN)
    : 300;

const PRESENCE_IP_MAX =
  Number(process.env.PPT_SHARE_PRESENCE_RATE_LIMIT_IP) > 0
    ? Number(process.env.PPT_SHARE_PRESENCE_RATE_LIMIT_IP)
    : 120;

const COMMENT_READ_IP_MAX =
  Number(process.env.PPT_SHARE_COMMENT_READ_RATE_LIMIT_IP) > 0
    ? Number(process.env.PPT_SHARE_COMMENT_READ_RATE_LIMIT_IP)
    : 120;

/** Writes are far cheaper to abuse than reads, so they get their own tighter buckets. */
const COMMENT_WRITE_IP_MAX =
  Number(process.env.PPT_SHARE_COMMENT_WRITE_RATE_LIMIT_IP) > 0
    ? Number(process.env.PPT_SHARE_COMMENT_WRITE_RATE_LIMIT_IP)
    : 20;

const COMMENT_WRITE_TOKEN_MAX =
  Number(process.env.PPT_SHARE_COMMENT_WRITE_RATE_LIMIT_TOKEN) > 0
    ? Number(process.env.PPT_SHARE_COMMENT_WRITE_RATE_LIMIT_TOKEN)
    : 60;

const ipHash = (ip) =>
  crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex').slice(0, 32);

async function getBucketState(key, max) {
  const windowMs = WINDOW_SEC * 1000;
  const now = Date.now();

  await redisClient.zRemRangeByScore(key, 0, now - windowMs);
  const count = await redisClient.zCard(key);

  if (count >= max) {
    const oldest = await redisClient.zRangeWithScores(key, 0, 0);
    let retryAfterSec = WINDOW_SEC;
    if (oldest.length > 0) {
      const oldestScore = Number(oldest[0].score);
      retryAfterSec = Math.max(1, Math.ceil((oldestScore + windowMs - now) / 1000));
    }
    return { blocked: true, retryAfterSec };
  }

  return { blocked: false, retryAfterSec: 0 };
}

async function recordRequest(key) {
  const now = Date.now();
  await redisClient.zAdd(key, { score: now, value: `${now}:${crypto.randomUUID()}` });
  await redisClient.expire(key, WINDOW_SEC);
}

async function assertAllowed(buckets) {
  const states = await Promise.all(buckets.map(({ key, max }) => getBucketState(key, max)));
  const blocked = states.filter((state) => state.blocked);

  if (blocked.length > 0) {
    const err = new AppError(messages.PRESENTATION_SHARE_RATE_LIMITED, 429);
    err.retryAfterSec = Math.max(...blocked.map((state) => state.retryAfterSec));
    throw err;
  }

  await Promise.all(buckets.map(({ key }) => recordRequest(key)));
}

async function assertViewAllowed({ ip, tokenHash }) {
  return assertAllowed([
    { key: `ppt:share:view:ip:${ipHash(ip)}`, max: VIEW_IP_MAX },
    { key: `ppt:share:view:token:${tokenHash}`, max: VIEW_TOKEN_MAX },
  ]);
}

async function assertPresenceAllowed({ ip }) {
  return assertAllowed([{ key: `ppt:share:presence:ip:${ipHash(ip)}`, max: PRESENCE_IP_MAX }]);
}

async function assertCommentReadAllowed({ ip }) {
  return assertAllowed([
    { key: `ppt:share:comment:read:ip:${ipHash(ip)}`, max: COMMENT_READ_IP_MAX },
  ]);
}

async function assertCommentWriteAllowed({ ip, tokenHash }) {
  return assertAllowed([
    { key: `ppt:share:comment:write:ip:${ipHash(ip)}`, max: COMMENT_WRITE_IP_MAX },
    { key: `ppt:share:comment:write:token:${tokenHash}`, max: COMMENT_WRITE_TOKEN_MAX },
  ]);
}

module.exports = {
  WINDOW_SEC,
  VIEW_IP_MAX,
  VIEW_TOKEN_MAX,
  PRESENCE_IP_MAX,
  COMMENT_READ_IP_MAX,
  COMMENT_WRITE_IP_MAX,
  COMMENT_WRITE_TOKEN_MAX,
  assertViewAllowed,
  assertPresenceAllowed,
  assertCommentReadAllowed,
  assertCommentWriteAllowed,
};
