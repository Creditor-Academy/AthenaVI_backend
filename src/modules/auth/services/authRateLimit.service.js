const crypto = require('crypto');
const { redisClient } = require('../../../shared/config/redis');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const logger = require('../../../shared/utils/logger');
const { normalizeEmail } = require('../../../shared/utils/normalizeEmail');

const WINDOW_SEC =
  Number(process.env.LOGIN_RATE_LIMIT_WINDOW_SEC) > 0
    ? Number(process.env.LOGIN_RATE_LIMIT_WINDOW_SEC)
    : 15 * 60;

const ACCOUNT_LIMIT =
  Number(process.env.LOGIN_RATE_LIMIT_ACCOUNT) > 0
    ? Number(process.env.LOGIN_RATE_LIMIT_ACCOUNT)
    : 10;

const IP_LIMIT =
  Number(process.env.LOGIN_RATE_LIMIT_IP) > 0
    ? Number(process.env.LOGIN_RATE_LIMIT_IP)
    : 30;

const acctKey = (email) => `login:acct:${normalizeEmail(email)}`;
const ipKey = (ip) => `login:ip:${ip || 'unknown'}`;

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
    return { blocked: true, retryAfterSec, remaining: 0 };
  }

  return {
    blocked: false,
    retryAfterSec: 0,
    remaining: Math.max(0, max - count),
  };
}

async function recordFailure(key) {
  const now = Date.now();
  const member = `${now}:${crypto.randomUUID()}`;

  await redisClient.zAdd(key, { score: now, value: member });
  await redisClient.expire(key, WINDOW_SEC);
}

async function getLimitStatus({ email, ip }) {
  const [account, ipBucket] = await Promise.all([
    getBucketState(acctKey(email), ACCOUNT_LIMIT),
    getBucketState(ipKey(ip), IP_LIMIT),
  ]);

  const blocked = account.blocked || ipBucket.blocked;
  const retryAfterSec = Math.max(account.retryAfterSec, ipBucket.retryAfterSec);

  let bucket = null;
  if (account.blocked && ipBucket.blocked) {
    bucket = 'both';
  } else if (account.blocked) {
    bucket = 'account';
  } else if (ipBucket.blocked) {
    bucket = 'ip';
  }

  return { blocked, retryAfterSec, bucket, account, ipBucket };
}

async function assertLoginAllowed({ email, ip }) {
  const status = await getLimitStatus({ email, ip });

  if (status.blocked) {
    logger.warn('Login rate limit exceeded', {
      email: normalizeEmail(email),
      ip,
      bucket: status.bucket,
    });

    const err = new AppError(messages.TOO_MANY_LOGIN_ATTEMPTS, 429);
    err.retryAfterSec = status.retryAfterSec;
    throw err;
  }
}

async function recordLoginFailure({ email, ip }) {
  await Promise.all([
    recordFailure(acctKey(email)),
    recordFailure(ipKey(ip)),
  ]);
}

async function clearLoginAttempts({ email, ip }) {
  await Promise.all([
    redisClient.del(acctKey(email)),
    redisClient.del(ipKey(ip)),
  ]);
}

async function getRetryAfterSeconds({ email, ip }) {
  const status = await getLimitStatus({ email, ip });
  return status.retryAfterSec;
}

module.exports = {
  assertLoginAllowed,
  recordLoginFailure,
  clearLoginAttempts,
  getRetryAfterSeconds,
};
