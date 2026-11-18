const Redis = require('ioredis');

/**
 * Connection options for BullMQ 6 queues and workers.
 *
 * BullMQ 6 does not bundle a Redis client. ioredis is installed for it, and
 * BullMQ opens its own clients from these options. Do not pass the node-redis
 * client from src/shared/config/redis.js. Workers need maxRetriesPerRequest
 * set to null so a blocking command is not cut off.
 *
 * Uses BULLMQ_REDIS_URL when set, otherwise REDIS_URL. Production should set
 * BULLMQ_REDIS_URL to the ElastiCache primary endpoint. Render Key Value can
 * stay on REDIS_URL for sessions, but its eviction policy cannot be changed.
 *
 * rediss:// enables TLS. Both the Render external URL and an encrypted
 * ElastiCache endpoint use that scheme.
 */
function getBullmqRedisUrl() {
  return String(process.env.BULLMQ_REDIS_URL || process.env.REDIS_URL || '').trim();
}

function getBullmqConnectionOptions() {
  const url = getBullmqRedisUrl();
  if (!url) {
    throw new Error('REDIS_URL or BULLMQ_REDIS_URL is required for BullMQ');
  }
  return {
    url,
    maxRetriesPerRequest: null,
  };
}

/**
 * Reads maxmemory_policy. BullMQ jobs are unsafe unless it is noeviction.
 * Does not throw: callers log the result. A failed check must not stop the API.
 */
async function checkBullmqRedis() {
  const url = getBullmqRedisUrl();
  const urlSource = String(process.env.BULLMQ_REDIS_URL || '').trim()
    ? 'BULLMQ_REDIS_URL'
    : 'REDIS_URL';
  if (!url) {
    return { ok: false, policy: 'missing', urlSource: 'none' };
  }

  const redis = new Redis(url, {
    maxRetriesPerRequest: 1,
    connectTimeout: 10_000,
    lazyConnect: true,
  });
  try {
    await redis.connect();
    const info = await redis.info('memory');
    const policy = (String(info).match(/maxmemory_policy:(\S+)/) || [])[1] || 'unknown';
    return { ok: policy === 'noeviction', policy, urlSource };
  } finally {
    redis.disconnect();
  }
}

module.exports = {
  getBullmqRedisUrl,
  getBullmqConnectionOptions,
  checkBullmqRedis,
};
