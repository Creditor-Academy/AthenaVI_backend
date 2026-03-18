const Queue = require('bull');

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

// Bull uses ioredis; pass options derived from URL for compatibility
function getRedisOpts() {
  try {
    const u = new URL(redisUrl);
    const opts = {
      host: u.hostname || 'localhost',
      port: parseInt(u.port, 10) || 6379,
    };
    if (u.password) opts.password = u.password;
    if (u.protocol === 'rediss:') opts.tls = {};
    return opts;
  } catch {
    return { host: 'localhost', port: 6379 };
  }
}

const renderQueue = new Queue('video-render', {
  redis: getRedisOpts(),
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 500 },
  },
});

module.exports = { renderQueue };
