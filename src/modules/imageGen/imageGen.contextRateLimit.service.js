const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const WINDOW_SEC =
  Number(process.env.IMAGE_GEN_CONTEXT_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_RATE_LIMIT_WINDOW_SEC)
    : 3600;

const MAX =
  Number(process.env.IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_RATE_LIMIT_MAX)
    : 20;

const userKey = (userId) => `imageGen:context:hour:user:${userId || 'unknown'}`;

function resetAtFromRetry(retryAfterSec) {
  if (!retryAfterSec || retryAfterSec <= 0) {
    return null;
  }
  return new Date(Date.now() + retryAfterSec * 1000).toISOString();
}

async function readBucket(key, max, windowSec) {
  const raw = await redisClient.get(key);
  const count = raw == null ? 0 : Number(raw) || 0;
  const ttl = await redisClient.ttl(key);
  const retryAfterSec = count > 0 ? Math.max(1, ttl > 0 ? ttl : windowSec) : 0;
  return {
    count,
    remaining: Math.max(0, max - count),
    blocked: count >= max,
    retryAfterSec,
    resetAt: resetAtFromRetry(retryAfterSec),
  };
}

function toHourState(bucket) {
  return {
    limit: MAX,
    used: bucket.count,
    remaining: bucket.remaining,
    resetAt: bucket.resetAt,
    retryAfterSec: bucket.retryAfterSec,
  };
}

async function getContextHourState(userId) {
  return toHourState(await readBucket(userKey(userId), MAX, WINDOW_SEC));
}

async function takeSlot(key, windowSec) {
  const count = await redisClient.incr(key);
  const ttl = await redisClient.ttl(key);
  if (count === 1 || ttl < 0) {
    await redisClient.expire(key, windowSec);
  }
}

async function assertContextCreateAllowed(userId) {
  const userState = await readBucket(userKey(userId), MAX, WINDOW_SEC);

  if (userState.blocked) {
    const hour = toHourState(userState);
    const err = new AppError(messages.IMAGE_GEN_CONTEXT_RATE_LIMITED, 429);
    err.retryAfterSec = hour.retryAfterSec;
    err.resetAt = hour.resetAt;
    err.remaining = 0;
    err.limit = MAX;
    throw err;
  }

  await takeSlot(userKey(userId), WINDOW_SEC);

  return getContextHourState(userId);
}

module.exports = {
  assertContextCreateAllowed,
  getContextHourState,
  MAX,
  WINDOW_SEC,
};
