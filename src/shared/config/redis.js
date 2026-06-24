const { createClient } = require("redis");

const DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
const connectTimeout = Number(process.env.REDIS_CONNECT_TIMEOUT) || DEFAULT_CONNECT_TIMEOUT_MS;

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    connectTimeout,
    reconnectStrategy: (retries) => Math.min(retries * 50, 500),
  },
});

redisClient.on("connect", () => {
  console.log("Redis connected");
});

redisClient.on("error", (err) => {
  console.error("Redis error:", err);
});

const connectRedis = async () => {
  const redisUrl = process.env.REDIS_URL || "";
  if (
    redisUrl.includes("keyvalue.render.com") ||
    redisUrl.includes("oregon-keyvalue.render.com")
  ) {
    console.warn(
      "REDIS_URL looks like an external Render Key Value URL. " +
        "On Render web services, use the Internal Redis URL from the Key Value Connect tab " +
        "(ipAllowList blocks external clients).",
    );
  }

  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
};

module.exports = {
  redisClient,
  connectRedis,
};
