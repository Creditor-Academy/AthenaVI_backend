const { createClient } = require('redis');
const AppError = require('../utils/AppError');
const messages = require('../utils/messages');

const DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
const connectTimeout = Number(process.env.REDIS_CONNECT_TIMEOUT) || DEFAULT_CONNECT_TIMEOUT_MS;

/** Set true only after a successful connect(); cleared on terminal connection errors. */
let redisReady = false;
/** When true, client will not reconnect (e.g. allowlisted cloud Redis from local dev). */
let redisDisabled = false;
let lastRedisErrorLogAt = 0;

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    connectTimeout,
    reconnectStrategy: (retries) => {
      if (redisDisabled) return false;
      return Math.min(retries * 50, 500);
    },
  },
});

function isRedisOptional() {
  if (process.env.REDIS_OPTIONAL === 'true') return true;
  if (process.env.REDIS_OPTIONAL === 'false') return false;
  return process.env.NODE_ENV === 'development';
}

function isRedisReady() {
  return redisReady && redisClient.isOpen;
}

function logRedisErrorOnce(err) {
  const now = Date.now();
  if (now - lastRedisErrorLogAt < 15_000) return;
  lastRedisErrorLogAt = now;
  console.error('Redis error:', err?.message || err);
}

redisClient.on('connect', () => {
  redisReady = true;
  console.log('Redis connected');
});

redisClient.on('ready', () => {
  redisReady = true;
});

redisClient.on('end', () => {
  redisReady = false;
});

redisClient.on('error', (err) => {
  redisReady = false;
  logRedisErrorOnce(err);
});

function markRedisDisabled(reason) {
  redisDisabled = true;
  redisReady = false;
  if (reason) {
    logRedisErrorOnce(reason instanceof Error ? reason : new Error(String(reason)));
  }
}

function assertRedisReady() {
  if (redisDisabled || !isRedisReady()) {
    throw new AppError(messages.REDIS_UNAVAILABLE, 503);
  }
}

const connectRedis = async () => {
  const redisUrl = String(process.env.REDIS_URL || '').trim();
  if (!redisUrl) {
    console.warn('REDIS_URL not set; Redis-backed features (sessions, OTP, rate limits) are disabled.');
    redisReady = false;
    return false;
  }

  if (
    redisUrl.includes('keyvalue.render.com') ||
    redisUrl.includes('oregon-keyvalue.render.com')
  ) {
    console.warn(
      'REDIS_URL looks like an external Render Key Value URL. ' +
        'On Render web services, use the Internal Redis URL from the Key Value Connect tab ' +
        '(ipAllowList blocks external clients). For local dev, set REDIS_OPTIONAL=true or use a local Redis.',
    );
  }

  if (redisClient.isOpen) {
    redisReady = true;
    return true;
  }

  try {
    await redisClient.connect();
    redisReady = true;
    return true;
  } catch (err) {
    redisReady = false;
    if (isRedisOptional()) {
      markRedisDisabled(err);
      console.warn(
        `Redis connect failed (continuing without Redis): ${err?.message || err}. ` +
          'Fix REDIS_URL, allowlist your IP, or run local Redis. OTP/login sessions require Redis.',
      );
      return false;
    }
    throw err;
  }
};

module.exports = {
  redisClient,
  connectRedis,
  isRedisReady,
  isRedisOptional,
  assertRedisReady,
};
