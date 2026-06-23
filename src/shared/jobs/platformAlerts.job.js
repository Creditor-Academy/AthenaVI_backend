const { checkHeygenWalletAlert } = require('../../modules/superadmin/superadminAlerts.service');
const { PLATFORM_ALERTS_JOB_INTERVAL_MS } = require('../config/notificationThresholds');
const logger = require('../utils/logger');

function startPlatformAlertsJob() {
  const intervalMs = PLATFORM_ALERTS_JOB_INTERVAL_MS;

  const run = async () => {
    try {
      const result = await checkHeygenWalletAlert();
      if (result.alerted) {
        logger.info('Platform HeyGen wallet low alert dispatched', {
          remainingBalanceUsd: result.remainingBalanceUsd,
        });
      }
    } catch (error) {
      logger.error('Platform alerts job failed', { error: error.message });
    }
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();

  logger.info('Platform alerts job scheduled', { intervalMs });
}

module.exports = {
  startPlatformAlertsJob,
};
