const { redisClient } = require('../../shared/config/redis');
const crypto = require('crypto');

const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days

const createSession = async ({ userId, userAgent, ip }) => {
  const sessionId = crypto.randomUUID();

  await redisClient.set(
    `session:${sessionId}`,
    JSON.stringify({
      userId,
      userAgent,
      ip,
      createdAt: Date.now(),
    }),
    { EX: SESSION_TTL }
  );

  return sessionId;
};

const findSession = async ({ sessionId }) => {
  return await redisClient.get(`session:${sessionId}`);
};

const deleteSession = async ({ sessionId }) => {
  console.log(sessionId);

  await redisClient.del(`session:${sessionId}`);
};

module.exports = { createSession, findSession, deleteSession };
