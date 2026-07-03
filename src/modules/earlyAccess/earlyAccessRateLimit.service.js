const crypto = require('crypto');
const { redisClient } = require('../../shared/config/redis');
const EarlyAccessHttpError = require('./earlyAccess.errors');
const messages = require('../../shared/utils/messages');

const WINDOW_SEC =
  Number(process.env.EARLY_ACCESS_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.EARLY_ACCESS_RATE_LIMIT_WINDOW_SEC)
    : 3600;

const IP_LIMIT =
  Number(process.env.EARLY_ACCESS_RATE_LIMIT_MAX) > 0
    ? Number(process.env.EARLY_ACCESS_RATE_LIMIT_MAX)
    : 3;

const ipKey = (ip) => `early-access:ip:${ip || 'unknown'}`;

async function pruneAndCount(key, windowMs) {
  const now = Date.now();
  const windowStart = now - windowMs;

  await redisClient.zRemRangeByScore(key, 0, windowStart);
  const count = await redisClient.zCard(key);

  return { count, now };
}

async function getBucketState(key, max) {
  const windowMs = WINDOW_SEC * 1000;
  const { count, now } = await pruneAndCount(key, windowMs);

  if (count >= max) {
    const oldest = await redisClient.zRangeWithScores(key, 0, 0);
    let retryAfterSec = WINDOW_SEC;
    if (oldest.length > 0) {
      const oldestScore = Number(oldest[0].score);
      retryAfterSec = Math.max(
        1,
        Math.ceil((oldestScore + windowMs - now) / 1000)
      );
    }
    return { blocked: true, retryAfterSec };
  }

  return { blocked: false, retryAfterSec: 0 };
}

async function recordRequest(key) {
  const now = Date.now();
  const member = `${now}:${crypto.randomUUID()}`;

  await redisClient.zAdd(key, { score: now, value: member });
  await redisClient.expire(key, WINDOW_SEC);
}

async function assertAllowed(ip) {
  const state = await getBucketState(ipKey(ip), IP_LIMIT);

  if (state.blocked) {
    throw new EarlyAccessHttpError({
      statusCode: 429,
      error: 'RATE_LIMIT_EXCEEDED',
      message: messages.EARLY_ACCESS_RATE_LIMITED,
      retryAfterSec: state.retryAfterSec,
    });
  }
}

async function recordSuccess(ip) {
  await recordRequest(ipKey(ip));
}

module.exports = {
  assertAllowed,
  recordSuccess,
};
