const crypto = require('crypto');
const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const GENERATE_WINDOW_SEC =
  Number(process.env.PPT_GENERATE_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.PPT_GENERATE_RATE_LIMIT_WINDOW_SEC)
    : 3600;

const GENERATE_MAX =
  Number(process.env.PPT_GENERATE_RATE_LIMIT_MAX) > 0
    ? Number(process.env.PPT_GENERATE_RATE_LIMIT_MAX)
    : 10;

const REGENERATE_WINDOW_SEC =
  Number(process.env.PPT_REGENERATE_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.PPT_REGENERATE_RATE_LIMIT_WINDOW_SEC)
    : 3600;

const REGENERATE_MAX =
  Number(process.env.PPT_REGENERATE_RATE_LIMIT_MAX) > 0
    ? Number(process.env.PPT_REGENERATE_RATE_LIMIT_MAX)
    : 30;

const userGenerateKey = (userId) => `ppt:generate:user:${userId || 'unknown'}`;
const workspaceGenerateKey = (workspaceId) =>
  `ppt:generate:workspace:${workspaceId || 'unknown'}`;
const userRegenerateKey = (userId) => `ppt:regenerate:user:${userId || 'unknown'}`;
const workspaceRegenerateKey = (workspaceId) =>
  `ppt:regenerate:workspace:${workspaceId || 'unknown'}`;

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

async function assertBucketsAllowed({ userKey, workspaceKey, max, windowSec }) {
  const [userState, workspaceState] = await Promise.all([
    getBucketState(userKey, max, windowSec),
    getBucketState(workspaceKey, max, windowSec),
  ]);

  if (userState.blocked || workspaceState.blocked) {
    const err = new AppError(messages.PRESENTATION_RATE_LIMITED, 429);
    err.retryAfterSec = Math.max(userState.retryAfterSec, workspaceState.retryAfterSec);
    throw err;
  }

  await Promise.all([
    recordRequest(userKey, windowSec),
    recordRequest(workspaceKey, windowSec),
  ]);
}

async function assertGenerateAllowed(userId, workspaceId) {
  return assertBucketsAllowed({
    userKey: userGenerateKey(userId),
    workspaceKey: workspaceGenerateKey(workspaceId),
    max: GENERATE_MAX,
    windowSec: GENERATE_WINDOW_SEC,
  });
}

async function assertRegenerateAllowed(userId, workspaceId) {
  return assertBucketsAllowed({
    userKey: userRegenerateKey(userId),
    workspaceKey: workspaceRegenerateKey(workspaceId),
    max: REGENERATE_MAX,
    windowSec: REGENERATE_WINDOW_SEC,
  });
}

module.exports = {
  assertGenerateAllowed,
  assertRegenerateAllowed,
  GENERATE_MAX,
  GENERATE_WINDOW_SEC,
  REGENERATE_MAX,
  REGENERATE_WINDOW_SEC,
};
