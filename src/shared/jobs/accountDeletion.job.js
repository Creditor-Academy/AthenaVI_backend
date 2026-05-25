const { purgeExpiredAccounts } = require('../../modules/settings/accountDeletion.service');
const logger = require('../utils/logger');

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

function startAccountDeletionJob() {
  const intervalMs = Number(process.env.ACCOUNT_DELETION_JOB_INTERVAL_MS) || DEFAULT_INTERVAL_MS;

  const run = async () => {
    try {
      const deletedCount = await purgeExpiredAccounts();
      if (deletedCount > 0) {
        logger.info('Account deletion job completed', { deletedCount });
      }
    } catch (error) {
      logger.error('Account deletion job failed', { error: error.message });
    }
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();

  logger.info('Account deletion job scheduled', { intervalMs });
}

module.exports = {
  startAccountDeletionJob,
};
