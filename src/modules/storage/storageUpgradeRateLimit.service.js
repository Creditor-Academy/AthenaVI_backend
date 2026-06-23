const { redisClient } = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const COOLDOWN_SEC =
  Number(process.env.STORAGE_UPGRADE_REQUEST_COOLDOWN_SEC) > 0
    ? Number(process.env.STORAGE_UPGRADE_REQUEST_COOLDOWN_SEC)
    : 24 * 60 * 60;

const cooldownKey = (userId) => `storage:upgrade:req:${userId}`;

async function assertAllowed(userId) {
  const ttl = await redisClient.ttl(cooldownKey(userId));

  if (ttl > 0) {
    const err = new AppError(messages.STORAGE_UPGRADE_REQUEST_RATE_LIMITED, 429);
    err.retryAfterSec = ttl;
    throw err;
  }
}

async function recordSuccess(userId) {
  await redisClient.set(cooldownKey(userId), '1', { EX: COOLDOWN_SEC });
}

module.exports = {
  assertAllowed,
  recordSuccess,
};
