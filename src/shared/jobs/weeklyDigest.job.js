const { sendWeeklyDigests, getIsoWeekStart } = require('../../modules/notifications/weeklyDigest.service');
const { redisClient } = require('../config/redis');
const logger = require('../utils/logger');

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

function getIsoWeekKey(date = new Date()) {
  const weekStart = getIsoWeekStart(date);
  return weekStart.toISOString().slice(0, 10);
}

function shouldRunNow() {
  const enabled = process.env.WEEKLY_DIGEST_ENABLED !== 'false';
  if (!enabled) {
    return false;
  }

  const targetDay = Number(process.env.WEEKLY_DIGEST_DAY_UTC ?? 1);
  const targetHour = Number(process.env.WEEKLY_DIGEST_HOUR_UTC ?? 9);
  const now = new Date();

  return now.getUTCDay() === targetDay && now.getUTCHours() === targetHour;
}

function startWeeklyDigestJob() {
  const intervalMs = Number(process.env.WEEKLY_DIGEST_JOB_INTERVAL_MS) || DEFAULT_INTERVAL_MS;

  const run = async () => {
    if (!shouldRunNow()) {
      return;
    }

    const weekKey = getIsoWeekKey();
    const lockKey = `weekly_digest:lock:${weekKey}`;

    try {
      const acquired = await redisClient.set(lockKey, '1', { NX: true, EX: 86400 });
      if (!acquired) {
        return;
      }

      const result = await sendWeeklyDigests();
      if (result.sentCount > 0 || result.failedCount > 0) {
        logger.info('Weekly digest job completed', result);
      }
    } catch (error) {
      logger.error('Weekly digest job failed', { error: error.message });
    }
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();

  logger.info('Weekly digest job scheduled', { intervalMs });
}

module.exports = {
  startWeeklyDigestJob,
};
