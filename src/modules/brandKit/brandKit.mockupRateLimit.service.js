const crypto = require('crypto');
const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const WINDOW_SEC =
  Number(process.env.BRAND_KIT_MOCKUP_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.BRAND_KIT_MOCKUP_RATE_LIMIT_WINDOW_SEC)
    : 3600;

const MAX =
  Number(process.env.BRAND_KIT_MOCKUP_RATE_LIMIT_MAX) > 0
    ? Number(process.env.BRAND_KIT_MOCKUP_RATE_LIMIT_MAX)
    : 20;

const userKey = (userId) => `brandKit:mockup:user:${userId || 'unknown'}`;
const workspaceKey = (workspaceId) =>
  `brandKit:mockup:workspace:${workspaceId || 'unknown'}`;

async function pruneAndCount(key, windowMs) {
  const now = Date.now();
  const windowStart = now - windowMs;
  await redisClient.zRemRangeByScore(key, 0, windowStart);
  const count = await redisClient.zCard(key);
  return { count, now };
}

async function getBucketState(key, max, windowSec) {
  const windowMs = windowSec * 1000;
  const { count, now } = await pruneAndCount(key, windowMs);

  if (count >= max) {
    const oldest = await redisClient.zRangeWithScores(key, 0, 0);
    let retryAfterSec = windowSec;
    if (oldest.length > 0) {
      const oldestScore = Number(oldest[0].score);
      retryAfterSec = Math.max(1, Math.ceil((oldestScore + windowMs - now) / 1000));
    }
    return { blocked: true, retryAfterSec };
  }

  return { blocked: false, retryAfterSec: 0 };
}

async function recordRequest(key, windowSec) {
  const now = Date.now();
  const member = `${now}:${crypto.randomUUID()}`;
  await redisClient.zAdd(key, { score: now, value: member });
  await redisClient.expire(key, windowSec);
}

async function assertGenerateAllowed(userId, workspaceId) {
  const [userState, workspaceState] = await Promise.all([
    getBucketState(userKey(userId), MAX, WINDOW_SEC),
    getBucketState(workspaceKey(workspaceId), MAX, WINDOW_SEC),
  ]);

  if (userState.blocked || workspaceState.blocked) {
    const err = new AppError(messages.BRAND_KIT_MOCKUP_RATE_LIMITED, 429);
    err.retryAfterSec = Math.max(userState.retryAfterSec, workspaceState.retryAfterSec);
    throw err;
  }

  await Promise.all([
    recordRequest(userKey(userId), WINDOW_SEC),
    recordRequest(workspaceKey(workspaceId), WINDOW_SEC),
  ]);
}

module.exports = {
  assertGenerateAllowed,
};
