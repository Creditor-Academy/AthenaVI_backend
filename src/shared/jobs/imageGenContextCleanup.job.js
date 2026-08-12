const logger = require('../utils/logger');
const contextDao = require('../../modules/imageGen/imageGen.context.dao');
const { deleteFile } = require('../../modules/s3/s3.service');

const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;

async function purgeExpiredContexts({ take = 50 } = {}) {
  const rows = await contextDao.listExpiredUnpinned({ take });
  let deleted = 0;

  for (const row of rows) {
    for (const file of row.files || []) {
      if (file.source === 'upload' && file.s3Key) {
        try {
          // eslint-disable-next-line no-await-in-loop
          await deleteFile(file.s3Key);
        } catch (error) {
          logger.warn('Failed to delete image-gen context S3 key', {
            s3Key: file.s3Key,
            error: error.message,
          });
        }
      }
    }
    try {
      // eslint-disable-next-line no-await-in-loop
      await contextDao.deleteContext(row.id);
      deleted += 1;
    } catch (error) {
      logger.warn('Failed to delete image-gen context row', {
        contextId: row.id,
        error: error.message,
      });
    }
  }

  return deleted;
}

function startImageGenContextCleanupJob() {
  const intervalMs =
    Number(process.env.IMAGE_GEN_CONTEXT_CLEANUP_INTERVAL_MS) > 0
      ? Number(process.env.IMAGE_GEN_CONTEXT_CLEANUP_INTERVAL_MS)
      : DEFAULT_INTERVAL_MS;

  const run = async () => {
    try {
      const deletedCount = await purgeExpiredContexts();
      if (deletedCount > 0) {
        logger.info('Image gen context cleanup completed', { deletedCount });
      }
    } catch (error) {
      logger.error('Image gen context cleanup failed', { error: error.message });
    }
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();

  logger.info('Image gen context cleanup job scheduled', { intervalMs });
}

module.exports = {
  startImageGenContextCleanupJob,
  purgeExpiredContexts,
};
